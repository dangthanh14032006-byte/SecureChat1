using System.Net.Sockets;
using System.Numerics;
using SecureChat.Core.Crypto;
using SecureChat.Core.Protocol;

namespace SecureChat.Client;

/// <summary>Sự kiện có tin nhắn mới đến (đã giải mã) để lớp giao diện console hiển thị.</summary>
public sealed record IncomingChatEvent(string FromUsername, DecryptedMessage Message, DateTimeOffset Timestamp);

/// <summary>
/// Client chat: giữ kết nối TCP tới server, thực hiện đăng ký/đăng nhập, tra cứu khóa công khai,
/// mã hóa/giải mã tin nhắn đầu-cuối (AES-256-GCM + ElGamal + SHA-256/MD5 + chữ ký số),
/// và một vòng lặp nền để nhận tin nhắn đến bất kỳ lúc nào.
/// </summary>
public sealed class ChatClient : IAsyncDisposable
{
    private readonly TcpClient _tcp = new();
    private NetworkStream? _stream;
    private readonly StreamReadBuffer _readBuffer = new();
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private readonly object _pendingLock = new();
    private CancellationTokenSource? _readLoopCts;

    public string? Username { get; private set; }
    public ElGamalKeyPair? MyKeys { get; private set; }

    /// <summary>Bộ nhớ đệm khóa công khai của các người dùng khác đã tra cứu, tránh hỏi lại server mỗi lần.</summary>
    private readonly Dictionary<string, BigInteger> _peerKeyCache = new();

    public event Action<IncomingChatEvent>? OnIncomingMessage;
    public event Action<string>? OnServerError;

    public async Task ConnectAsync(string host, int port)
    {
        await _tcp.ConnectAsync(host, port);
        _stream = _tcp.GetStream();
        _readLoopCts = new CancellationTokenSource();
        _ = ReadLoopAsync(_readLoopCts.Token);
    }

    // --- Vòng lặp đọc nền: mọi gói tin đến đều qua đây; ChatIncoming được phát sự kiện ngay,
    // các phản hồi request/response khác được khớp bằng hàng đợi FIFO theo PacketType. ---
    private readonly Dictionary<PacketType, Queue<TaskCompletionSource<Packet>>> _waiters = new();

    private async Task ReadLoopAsync(CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                var packet = await WireCodec.ReadPacketAsync(_stream!, _readBuffer, ct);
                if (packet == null) break;

                if (packet.Type == PacketType.ChatIncoming)
                {
                    var incoming = WireCodec.ReadPayload<ChatIncoming>(packet);
                    await HandleIncomingAsync(incoming.Envelope);
                    continue;
                }

                TaskCompletionSource<Packet>? waiter = null;
                lock (_pendingLock)
                {
                    if (_waiters.TryGetValue(packet.Type, out var q) && q.Count > 0)
                        waiter = q.Dequeue();
                }
                waiter?.TrySetResult(packet);
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) { OnServerError?.Invoke($"Mất kết nối tới server: {ex.Message}"); }
    }

    private Task<Packet> WaitForAsync(PacketType type)
    {
        var tcs = new TaskCompletionSource<Packet>(TaskCreationOptions.RunContinuationsAsynchronously);
        lock (_pendingLock)
        {
            if (!_waiters.TryGetValue(type, out var q)) _waiters[type] = q = new();
            q.Enqueue(tcs);
        }
        return tcs.Task;
    }

    private async Task<TResp> RequestAsync<TReq, TResp>(PacketType reqType, TReq req, PacketType respType)
    {
        var waitTask = WaitForAsync(respType);
        await SendAsync(reqType, req);
        var packet = await waitTask;
        return WireCodec.ReadPayload<TResp>(packet);
    }

    private async Task SendAsync<T>(PacketType type, T payload)
    {
        await _writeLock.WaitAsync();
        try { await WireCodec.WritePacketAsync(_stream!, WireCodec.MakePacket(type, payload)); }
        finally { _writeLock.Release(); }
    }

    // --- Tài khoản & khóa ---

    /// <summary>Đăng ký tài khoản mới: sinh cặp khóa ElGamal cục bộ, lưu (mã hóa bằng mật khẩu), gửi khóa công khai lên server.</summary>
    public async Task<(bool ok, string message)> RegisterAsync(string username, string password, string keyDir)
    {
        var path = KeyStore.DefaultPath(username, keyDir);
        var keys = KeyStore.CreateAndSave(username, password, path);
        var resp = await RequestAsync<RegisterRequest, RegisterResponse>(
            PacketType.RegisterRequest,
            new RegisterRequest { Username = username, Password = password, PublicKeyB64 = BigIntUtil.ToB64(keys.PublicKeyY) },
            PacketType.RegisterResponse);

        if (resp.Success) { Username = username; MyKeys = keys; }
        return (resp.Success, resp.Message);
    }

    /// <summary>Đăng nhập: nạp lại khóa riêng từ đĩa bằng mật khẩu, xác thực với server.</summary>
    public async Task<(bool ok, string message)> LoginAsync(string username, string password, string keyDir)
    {
        var path = KeyStore.DefaultPath(username, keyDir);
        if (!KeyStore.Exists(path))
            return (false, "Không tìm thấy khóa cục bộ cho người dùng này trên máy này. Hãy đăng ký trước.");

        ElGamalKeyPair keys;
        try { keys = KeyStore.Load(password, path); }
        catch (Exception ex) { return (false, ex.Message); }

        var resp = await RequestAsync<LoginRequest, LoginResponse>(
            PacketType.LoginRequest,
            new LoginRequest { Username = username, Password = password },
            PacketType.LoginResponse);

        if (resp.Success) { Username = username; MyKeys = keys; }
        return (resp.Success, resp.Message);
    }

    public async Task<List<UserSummary>> ListUsersAsync()
    {
        var resp = await RequestAsync<ListUsersRequest, ListUsersResponse>(
            PacketType.ListUsersRequest, new ListUsersRequest(), PacketType.ListUsersResponse);
        return resp.Users;
    }

    private async Task<BigInteger> GetPeerPublicKeyAsync(string username)
    {
        if (_peerKeyCache.TryGetValue(username, out var cached)) return cached;

        var resp = await RequestAsync<PublicKeyRequest, PublicKeyResponse>(
            PacketType.PublicKeyRequest, new PublicKeyRequest { Username = username }, PacketType.PublicKeyResponse);
        if (!resp.Found) throw new InvalidOperationException($"Không tìm thấy người dùng '{username}'.");

        var key = BigIntUtil.FromB64(resp.PublicKeyB64);
        _peerKeyCache[username] = key;
        return key;
    }

    // --- Nhắn tin ---

    /// <summary>Mã hóa và gửi tin nhắn tới một người dùng. Trả về CryptoMetrics để hiển thị đánh giá hiệu năng/kích thước.</summary>
    public async Task<CryptoMetrics> SendChatAsync(string toUsername, string plaintext)
    {
        if (Username == null || MyKeys == null) throw new InvalidOperationException("Chưa đăng nhập.");
        var peerKey = await GetPeerPublicKeyAsync(toUsername);

        var envelope = HybridEncryption.Encrypt(Username, MyKeys, toUsername, peerKey, plaintext);
        await SendAsync(PacketType.ChatSend, new ChatSendRequest { Envelope = EnvelopeDto.From(envelope) });
        return envelope.Metrics!;
    }

    private async Task HandleIncomingAsync(EnvelopeDto dto)
    {
        if (MyKeys == null) return;
        try
        {
            var senderKey = await GetPeerPublicKeyAsync(dto.SenderId);
            var envelope = dto.ToEnvelope();
            var decrypted = HybridEncryption.Decrypt(envelope, MyKeys, senderKey);
            OnIncomingMessage?.Invoke(new IncomingChatEvent(dto.SenderId, decrypted, envelope.Timestamp));
        }
        catch (Exception ex)
        {
            OnServerError?.Invoke($"Không thể giải mã tin nhắn từ {dto.SenderId}: {ex.Message}");
        }
    }

    /// <summary>Tải lịch sử hội thoại với một người dùng và giải mã toàn bộ để hiển thị.</summary>
    public async Task<List<(string sender, DecryptedMessage msg, DateTimeOffset ts)>> LoadHistoryAsync(string withUsername)
    {
        if (MyKeys == null) throw new InvalidOperationException("Chưa đăng nhập.");
        var resp = await RequestAsync<HistoryRequest, HistoryResponse>(
            PacketType.HistoryRequest, new HistoryRequest { WithUsername = withUsername }, PacketType.HistoryResponse);

        var result = new List<(string, DecryptedMessage, DateTimeOffset)>();
        foreach (var dto in resp.Envelopes)
        {
            try
            {
                var otherParty = dto.SenderId == Username ? dto.ReceiverId : dto.SenderId;
                var otherKey = await GetPeerPublicKeyAsync(otherParty);
                var envelope = dto.ToEnvelope();
                var decrypted = HybridEncryption.Decrypt(envelope, MyKeys, otherKey);
                result.Add((dto.SenderId, decrypted, envelope.Timestamp));
            }
            catch (Exception ex)
            {
                OnServerError?.Invoke($"Bỏ qua một tin nhắn lịch sử không giải mã được: {ex.Message}");
            }
        }
        return result;
    }

    public async ValueTask DisposeAsync()
    {
        _readLoopCts?.Cancel();
        _stream?.Close();
        _tcp.Close();
        await Task.CompletedTask;
    }
}

public sealed class ListUsersRequest { }
