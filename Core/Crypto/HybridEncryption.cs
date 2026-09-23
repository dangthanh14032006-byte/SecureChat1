using System.Diagnostics;
using System.Numerics;
using System.Text;

namespace SecureChat.Core.Crypto;

/// <summary>
/// Thước đo hiệu năng và kích thước của một lần mã hóa/giải mã - phục vụ mục
/// "đánh giá thời gian mã hóa/giải mã" và "đánh giá kích thước dữ liệu sau mã hóa".
/// </summary>
public sealed class CryptoMetrics
{
    public double EncryptMs { get; init; }
    public double DecryptMs { get; init; }
    public int PlaintextBytes { get; init; }
    public int CiphertextBytes { get; init; }
    public double Overhead => PlaintextBytes == 0 ? 0 : (double)CiphertextBytes / PlaintextBytes;

    public override string ToString() =>
        $"mã hóa={EncryptMs:F3}ms, giải mã={DecryptMs:F3}ms, " +
        $"gốc={PlaintextBytes}B, mã hóa={CiphertextBytes}B, hệ số phình={Overhead:F2}x";
}

/// <summary>
/// Gói tin đã mã hóa hoàn chỉnh gửi qua mạng / lưu vào lịch sử. Mô hình lai (hybrid):
///  - Nội dung tin nhắn: AES-256-GCM (nhanh, phù hợp dữ liệu dài, tự có xác thực AEAD).
///  - Khóa phiên AES: mã hóa bằng ElGamal với khóa công khai người nhận (trao khóa an toàn).
///  - SHA-256 của bản rõ: đảm bảo toàn vẹn ở tầng ứng dụng, người nhận đối chiếu sau khi giải mã.
///  - MD5 của bản rõ: chỉ dùng làm checksum nhanh tham khảo / so sánh hiệu năng, KHÔNG dùng để xác thực.
///  - Chữ ký số ElGamal của người gửi trên (SHA-256 của toàn bộ gói mã hóa): xác thực nguồn gốc,
///    chống chối bỏ (non-repudiation) và phát hiện giả mạo gói tin.
/// </summary>
public sealed class EncryptedEnvelope
{
    public required string SenderId { get; init; }
    public required string ReceiverId { get; init; }
    public required DateTimeOffset Timestamp { get; init; }

    /// <summary>Khóa AES phiên, đã được mã hóa bằng ElGamal (khóa công khai người nhận).</summary>
    public required byte[] WrappedSessionKey { get; init; }

    /// <summary>Nội dung tin nhắn đã mã hóa AES-256-GCM: [nonce|ciphertext|tag].</summary>
    public required byte[] Ciphertext { get; init; }

    /// <summary>SHA-256(bản rõ), hex - dùng để đối chiếu toàn vẹn tầng ứng dụng.</summary>
    public required string Sha256Hex { get; init; }

    /// <summary>MD5(bản rõ), hex - chỉ tham khảo/so sánh hiệu năng, không dùng để xác thực bảo mật.</summary>
    public required string Md5Hex { get; init; }

    /// <summary>Chữ ký số ElGamal của người gửi trên SHA-256(SenderId|ReceiverId|Timestamp|WrappedSessionKey|Ciphertext).</summary>
    public required byte[] Signature { get; init; }

    public CryptoMetrics? Metrics { get; init; }

    /// <summary>Dữ liệu chuẩn hóa dùng làm đầu vào cho chữ ký / xác minh, để tránh giả mạo bất kỳ trường nào.</summary>
    public byte[] BuildSignedPayload()
    {
        using var ms = new MemoryStream();
        void WriteStr(string s) { var b = Encoding.UTF8.GetBytes(s); WriteInt(b.Length); ms.Write(b); }
        void WriteInt(int v) => ms.Write(BitConverter.GetBytes(v));
        void WriteBytes(byte[] b) { WriteInt(b.Length); ms.Write(b); }

        WriteStr(SenderId);
        WriteStr(ReceiverId);
        ms.Write(BitConverter.GetBytes(Timestamp.ToUnixTimeMilliseconds()));
        WriteBytes(WrappedSessionKey);
        WriteBytes(Ciphertext);
        WriteStr(Sha256Hex);
        return ms.ToArray();
    }
}

/// <summary>Kết quả sau khi giải mã và xác minh một gói tin.</summary>
public sealed class DecryptedMessage
{
    public required string PlaintextUtf8 { get; init; }
    public required bool SignatureValid { get; init; }
    public required bool Sha256Match { get; init; }
    public required bool Md5Match { get; init; }
    public required CryptoMetrics Metrics { get; init; }
    public bool FullyTrusted => SignatureValid && Sha256Match;
}

/// <summary>
/// Lắp ráp/tháo gỡ EncryptedEnvelope: điều phối AES-GCM + ElGamal + SHA-256/MD5 + chữ ký số.
/// </summary>
public static class HybridEncryption
{
    /// <summary>
    /// Mã hóa tin nhắn văn bản để gửi từ senderKeys tới receiverPublicKey.
    /// </summary>
    public static EncryptedEnvelope Encrypt(
        string senderId, ElGamalKeyPair senderKeys,
        string receiverId, BigInteger receiverPublicKey,
        string plaintext)
    {
        var sw = Stopwatch.StartNew();

        var plainBytes = Encoding.UTF8.GetBytes(plaintext);
        var sessionKey = AesGcmCipher.GenerateKey();
        var ciphertext = AesGcmCipher.Encrypt(sessionKey, plainBytes);
        var wrappedKey = ElGamal.Encrypt(sessionKey, receiverPublicKey);

        var sha256Hex = HashUtil.Hex(HashUtil.Sha256(plainBytes));
        var md5Hex = HashUtil.Hex(HashUtil.Md5(plainBytes));

        var envelopeStub = new EncryptedEnvelope
        {
            SenderId = senderId,
            ReceiverId = receiverId,
            Timestamp = DateTimeOffset.UtcNow,
            WrappedSessionKey = wrappedKey,
            Ciphertext = ciphertext,
            Sha256Hex = sha256Hex,
            Md5Hex = md5Hex,
            Signature = Array.Empty<byte>(),
        };
        var toSign = HashUtil.Sha256(envelopeStub.BuildSignedPayload());
        var signature = ElGamalSigner.Sign(toSign, senderKeys.PrivateKeyX).ToBytes();

        sw.Stop();
        int cipherTotal = wrappedKey.Length + ciphertext.Length + signature.Length + 32 /* sha256 */ + 16 /* md5 */;

        var metrics = new CryptoMetrics
        {
            EncryptMs = sw.Elapsed.TotalMilliseconds,
            DecryptMs = 0,
            PlaintextBytes = plainBytes.Length,
            CiphertextBytes = cipherTotal,
        };

        return new EncryptedEnvelope
        {
            SenderId = senderId,
            ReceiverId = receiverId,
            Timestamp = envelopeStub.Timestamp,
            WrappedSessionKey = wrappedKey,
            Ciphertext = ciphertext,
            Sha256Hex = sha256Hex,
            Md5Hex = md5Hex,
            Signature = signature,
            Metrics = metrics,
        };
    }

    /// <summary>
    /// Giải mã ở phía người nhận: mở khóa phiên bằng ElGamal, giải mã AES-GCM, xác minh chữ ký
    /// số của người gửi và đối chiếu SHA-256/MD5 để phát hiện mọi sai lệch.
    /// </summary>
    public static DecryptedMessage Decrypt(
        EncryptedEnvelope envelope, ElGamalKeyPair receiverKeys, BigInteger senderPublicKey)
    {
        var sw = Stopwatch.StartNew();

        var toSign = HashUtil.Sha256(envelope.BuildSignedPayload());
        bool sigValid = ElGamalSigner.Verify(toSign, ElGamalSignature.FromBytes(envelope.Signature), senderPublicKey);

        var sessionKey = ElGamal.Decrypt(envelope.WrappedSessionKey, receiverKeys.PrivateKeyX);
        var plainBytes = AesGcmCipher.Decrypt(sessionKey, envelope.Ciphertext); // ném lỗi nếu bị giả mạo

        bool shaMatch = HashUtil.Hex(HashUtil.Sha256(plainBytes)) == envelope.Sha256Hex;
        bool md5Match = HashUtil.Hex(HashUtil.Md5(plainBytes)) == envelope.Md5Hex;

        sw.Stop();
        int cipherTotal = envelope.WrappedSessionKey.Length + envelope.Ciphertext.Length +
                           envelope.Signature.Length + 32 + 16;

        var metrics = new CryptoMetrics
        {
            EncryptMs = 0,
            DecryptMs = sw.Elapsed.TotalMilliseconds,
            PlaintextBytes = plainBytes.Length,
            CiphertextBytes = cipherTotal,
        };

        return new DecryptedMessage
        {
            PlaintextUtf8 = Encoding.UTF8.GetString(plainBytes),
            SignatureValid = sigValid,
            Sha256Match = shaMatch,
            Md5Match = md5Match,
            Metrics = metrics,
        };
    }
}
