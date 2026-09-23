using System.Security.Cryptography;
using System.Text.Json;
using SecureChat.Core.Crypto;

namespace SecureChat.Core.Services;

public sealed class UserAccount
{
    public string Username { get; set; } = "";
    public string SaltB64 { get; set; } = "";
    public int Iterations { get; set; }
    public string PasswordHashB64 { get; set; } = "";
    public string KeySaltB64 { get; set; } = "";
    public int KeyIterations { get; set; }
    public string EncryptedPrivateKeyB64 { get; set; } = ""; 
    public string PublicKeyB64 { get; set; } = "";
}

public sealed class UserStore
{
    private const int Pbkdf2Iterations = 200_000;

    private readonly string _path;

    private readonly Dictionary<string, UserAccount> _users =
        new(StringComparer.OrdinalIgnoreCase);

    private readonly object _lock = new();

    public UserStore(string path)
    {
        _path = path;
        Load();
    }

    private void Load()
    {
        if (!File.Exists(_path))
            return;

        var list =
            JsonSerializer.Deserialize<List<UserAccount>>(
                File.ReadAllText(_path)
            ) ?? new();

        foreach (var user in list)
            _users[user.Username] = user;
    }

    private void Persist()
    {
        var directory =
            Path.GetDirectoryName(
                Path.GetFullPath(_path)
            );

        if (directory != null)
            Directory.CreateDirectory(directory);

        File.WriteAllText(
            _path,
            JsonSerializer.Serialize(_users.Values.ToList())
        );
    }

    public bool TryRegister(
        string username,
        string password,
        string publicKeyB64,
        out string error)
    {
        lock (_lock)
        {
            if (string.IsNullOrWhiteSpace(username) ||
                username.Length < 3)
            {
                error = "Tên đăng nhập phải có ít nhất 3 ký tự.";
                return false;
            }

            if (password.Length < 6)
            {
                error = "Mật khẩu phải có ít nhất 6 ký tự.";
                return false;
            }

            if (_users.ContainsKey(username))
            {
                error = "Tên đăng nhập đã tồn tại.";
                return false;
            }

            var salt =
                RandomNumberGenerator.GetBytes(16);

            var hash =
                HashUtil.Pbkdf2(
                    password,
                    salt,
                    Pbkdf2Iterations,
                    32
                );

            _users[username] = new UserAccount
            {
                Username = username,

                SaltB64 =
                    Convert.ToBase64String(salt),

                Iterations =
                    Pbkdf2Iterations,

                PasswordHashB64 =
                    Convert.ToBase64String(hash),

                PublicKeyB64 =
                    publicKeyB64
            };

            Persist();

            error = "";
            return true;
        }
    }

    public bool TryLogin(
        string username,
        string password,
        out string error)
    {
        lock (_lock)
        {
            if (!_users.TryGetValue(username, out var user))
            {
                error = "Sai tên đăng nhập hoặc mật khẩu.";
                return false;
            }

            var salt =
                Convert.FromBase64String(user.SaltB64);

            var hash =
                HashUtil.Pbkdf2(
                    password,
                    salt,
                    user.Iterations,
                    32
                );

            var oldHash =
                Convert.FromBase64String(
                    user.PasswordHashB64
                );

            if (!CryptographicOperations.FixedTimeEquals(
                    hash,
                    oldHash))
            {
                error = "Sai tên đăng nhập hoặc mật khẩu.";
                return false;
            }

            error = "";
            return true;
        }
    }

    public bool SaveKeys(
    string username, string publicKeyB64,
    string encryptedPrivateKeyB64, string keySaltB64, int keyIterations)
    {
        lock (_lock)
        {
            if (!_users.TryGetValue(username, out var user)) return false;
            user.PublicKeyB64 = publicKeyB64;
            user.EncryptedPrivateKeyB64 = encryptedPrivateKeyB64;
            user.KeySaltB64 = keySaltB64;
            user.KeyIterations = keyIterations;
            Persist();
            return true;
        }
    }
    public UserAccount? Find(string username)
    {
        lock (_lock)
        {
            return _users.TryGetValue(
                username,
                out var user)
                ? user
                : null;
        }
    }

    public List<string> AllUsernames()
    {
        lock (_lock)
        {
            return _users.Keys.ToList();
        }
    }
}