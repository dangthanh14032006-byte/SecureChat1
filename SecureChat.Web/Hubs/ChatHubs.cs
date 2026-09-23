using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.SignalR;
using SecureChat.Core.Crypto;
using SecureChat.Core.Services;
using SecureChat.Web.Services;
using System.Numerics;
namespace SecureChat.Web.Hubs;

[Authorize]
public class ChatHub : Hub
{
    private readonly UserStore _users;
    private readonly KeySessionCache _keyCache;
    private readonly EncryptedMessageStore _messages;
    private readonly GroupStore _groups;
    private readonly GroupMessageStore _groupMessages;

    public ChatHub(
        UserStore users, KeySessionCache keyCache, EncryptedMessageStore messages,
        GroupStore groups, GroupMessageStore groupMessages)
    {
        _users = users;
        _keyCache = keyCache;
        _messages = messages;
        _groups = groups;
        _groupMessages = groupMessages;
    }
    public async Task SendMessage(string receiver, string message)
    {
        if (string.IsNullOrWhiteSpace(message)) return;
        var sender = Context.User?.Identity?.Name;
        if (string.IsNullOrWhiteSpace(sender)) return;
        if (!_keyCache.TryGet(sender, out var senderKeys)) return;

        var receiverAccount = _users.Find(receiver);
        var senderAccount = _users.Find(sender);
        if (receiverAccount == null || senderAccount == null) return;

        var receiverPub = BigIntUtil.FromB64(receiverAccount.PublicKeyB64);
        var senderPub = BigIntUtil.FromB64(senderAccount.PublicKeyB64);

        var forReceiver = HybridEncryption.Encrypt(sender, senderKeys, receiver, receiverPub, message);
        var forSenderCopy = HybridEncryption.Encrypt(sender, senderKeys, sender, senderPub, message);

        _messages.Add(new StoredMessage { ForReceiver = forReceiver, ForSenderCopy = forSenderCopy });

        // Giải mã thử ngay (nếu người nhận đang online) để đo thời gian giải mã thực tế
        // và xác minh chữ ký số + SHA-256 - phục vụ phần đánh giá của đề tài.
        DecryptedMessage? decrypted = null;
        if (_keyCache.TryGet(receiver, out var receiverKeys))
        {
            decrypted = HybridEncryption.Decrypt(forReceiver, receiverKeys, senderPub);
        }

        var metrics = new MessageMetricsDto
        {
            EncryptMs = forReceiver.Metrics!.EncryptMs,
            DecryptMs = decrypted?.Metrics.DecryptMs,
            PlaintextBytes = forReceiver.Metrics.PlaintextBytes,
            CiphertextBytes = forReceiver.Metrics.CiphertextBytes,
            Overhead = forReceiver.Metrics.Overhead,
            SignatureValid = decrypted?.SignatureValid,
            Sha256Match = decrypted?.Sha256Match
        };

        await Clients.User(receiver).SendAsync("ReceiveMessage", sender, message);
        await Clients.User(sender).SendAsync("ReceiveMessage", sender, message);
        await Clients.User(sender).SendAsync("ReceiveMetrics", metrics);

        if (decrypted != null)
            await Clients.User(receiver).SendAsync("ReceiveMetrics", metrics);
    }

    public async Task LoadHistory(string withUser)
    {
        var me = Context.User?.Identity?.Name;
        if (string.IsNullOrWhiteSpace(me)) return;
        if (!_keyCache.TryGet(me, out var myKeys)) return;

        var other = _users.Find(withUser);
        if (other == null) return;
        var otherPub = BigIntUtil.FromB64(other.PublicKeyB64);

        foreach (var stored in _messages.GetConversation(me, withUser))
        {
            var envelope = stored.ForReceiver.ReceiverId.Equals(me, StringComparison.OrdinalIgnoreCase)
                ? stored.ForReceiver
                : stored.ForSenderCopy;

            var decrypted = HybridEncryption.Decrypt(envelope, myKeys, otherPub);
            await Clients.Caller.SendAsync("ReceiveMessage", stored.ForReceiver.SenderId, decrypted.PlaintextUtf8);

            await Clients.Caller.SendAsync("ReceiveMetrics", new MessageMetricsDto
            {
                EncryptMs = envelope.Metrics?.EncryptMs ?? 0,
                DecryptMs = decrypted.Metrics.DecryptMs,
                PlaintextBytes = decrypted.Metrics.PlaintextBytes,
                CiphertextBytes = decrypted.Metrics.CiphertextBytes,
                Overhead = decrypted.Metrics.Overhead,
                SignatureValid = decrypted.SignatureValid,
                Sha256Match = decrypted.Sha256Match
            });
        }
    
}

    public async Task SendGroupMessage(string groupId, string message)
    {
        if (string.IsNullOrWhiteSpace(message)) return;
        var sender = Context.User?.Identity?.Name;
        if (string.IsNullOrWhiteSpace(sender)) return;
        if (!_keyCache.TryGet(sender, out var senderKeys)) return;

        var group = _groups.Find(groupId);
        if (group == null || !group.Members.Any(m => m.Equals(sender, StringComparison.OrdinalIgnoreCase))) return;

        var memberPublicKeys = new Dictionary<string, BigInteger>(StringComparer.OrdinalIgnoreCase);
        foreach (var member in group.Members)
        {
            var acc = _users.Find(member);
            if (acc != null) memberPublicKeys[member] = BigIntUtil.FromB64(acc.PublicKeyB64);
        }

        var envelope = GroupEncryption.Encrypt(groupId, sender, senderKeys, memberPublicKeys, message);
        _groupMessages.Add(envelope);

        foreach (var member in group.Members)
            await Clients.User(member).SendAsync("ReceiveGroupMessage", groupId, sender, message);
    }

    public async Task LoadGroupHistory(string groupId)
    {
        var me = Context.User?.Identity?.Name;
        if (string.IsNullOrWhiteSpace(me)) return;
        if (!_keyCache.TryGet(me, out var myKeys)) return;

        var group = _groups.Find(groupId);
        if (group == null || !group.Members.Any(m => m.Equals(me, StringComparison.OrdinalIgnoreCase))) return;

        foreach (var envelope in _groupMessages.GetForGroup(groupId))
        {
            var senderAcc = _users.Find(envelope.SenderId);
            if (senderAcc == null) continue;
            var senderPub = BigIntUtil.FromB64(senderAcc.PublicKeyB64);

            try
            {
                var (plaintext, sigValid, shaMatch) = GroupEncryption.Decrypt(envelope, me, myKeys, senderPub);
                await Clients.Caller.SendAsync("ReceiveGroupMessage", groupId, envelope.SenderId, plaintext);
            }
            catch
            {
                // Bỏ qua tin nhắn không giải mã được (ví dụ gửi trước khi mình vào nhóm)
            }
        }
    }
}
public sealed class MessageMetricsDto
{
    public double EncryptMs { get; init; }
    public double? DecryptMs { get; init; }
    public int PlaintextBytes { get; init; }
    public int CiphertextBytes { get; init; }
    public double Overhead { get; init; }
    public bool? SignatureValid { get; init; }
    public bool? Sha256Match { get; init; }
}