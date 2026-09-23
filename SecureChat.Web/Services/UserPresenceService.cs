namespace SecureChat.Web.Services;

public class UserPresenceService
{
    private readonly HashSet<string> _onlineUsers =
        new(StringComparer.OrdinalIgnoreCase);

    private readonly object _lock = new();

    public void UserConnected(string username)
    {
        if (string.IsNullOrWhiteSpace(username))
            return;

        lock (_lock)
        {
            _onlineUsers.Add(username);
        }
    }

    public void UserDisconnected(string username)
    {
        if (string.IsNullOrWhiteSpace(username))
            return;

        lock (_lock)
        {
            _onlineUsers.Remove(username);
        }
    }

    public bool IsOnline(string username)
    {
        lock (_lock)
        {
            return _onlineUsers.Contains(username);
        }
    }

    public List<string> GetOnlineUsers()
    {
        lock (_lock)
        {
            return _onlineUsers.ToList();
        }
    }
}