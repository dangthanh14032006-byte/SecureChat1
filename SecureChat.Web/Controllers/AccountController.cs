using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using SecureChat.Core.Services;
using SecureChat.Core.Crypto;
using System.Security.Cryptography;

namespace SecureChat.Web.Controllers;

public class AccountController : Controller
{
    private readonly UserStore _userStore;
    private readonly SecureChat.Web.Services.KeySessionCache _keyCache;

    public AccountController(UserStore userStore, SecureChat.Web.Services.KeySessionCache keyCache)
    {
        _userStore = userStore;
        _keyCache = keyCache;
    }

    [HttpGet]
    public IActionResult Register()
    {
        return View();
    }

    [HttpPost]
    public IActionResult Register(
        string username,
        string password,
        string confirmPassword)
    {
        if (password != confirmPassword)
        {
            ViewBag.Error =
                "Mật khẩu nhập lại không khớp.";

            return View();
        }

        var result = _userStore.TryRegister(
            username,
            password,
            "",
            out var error
        );

        if (!result)
        {
            ViewBag.Error = error;
            return View();
        }
        var keys = ElGamal.GenerateKeyPair();
        var keySalt = RandomNumberGenerator.GetBytes(16);
        var kek = HashUtil.Pbkdf2(password, keySalt, 200_000, AesGcmCipher.KeySize);
        var encryptedPriv = AesGcmCipher.Encrypt(kek, BigIntUtil.ToBytes(keys.PrivateKeyX));

        _userStore.SaveKeys(
            username,
            BigIntUtil.ToB64(keys.PublicKeyY),
            Convert.ToBase64String(encryptedPriv),
            Convert.ToBase64String(keySalt),
            200_000);
        ViewBag.Success =
            "Đăng ký thành công!";

        return View();
    }

    [HttpGet]
    public IActionResult Login()
    {
        return View();
    }

    [HttpPost]
    public async Task<IActionResult> Login(
        string username,
        string password)
    {
        var result = _userStore.TryLogin(
            username,
            password,
            out var error
        );

        if (!result)
        {
            ViewBag.Error = error;
            return View();
        }
        var account = _userStore.Find(username)!;
        var loginSalt = Convert.FromBase64String(account.KeySaltB64);
        var loginKek = HashUtil.Pbkdf2(password, loginSalt, account.KeyIterations, AesGcmCipher.KeySize);
        var privBytes = AesGcmCipher.Decrypt(loginKek, Convert.FromBase64String(account.EncryptedPrivateKeyB64));

        _keyCache.Set(username, new SecureChat.Core.Crypto.ElGamalKeyPair
        {
            PrivateKeyX = BigIntUtil.FromBytes(privBytes),
            PublicKeyY = BigIntUtil.FromB64(account.PublicKeyB64)
        });
        var claims = new List<System.Security.Claims.Claim>
{
    new System.Security.Claims.Claim(
        System.Security.Claims.ClaimTypes.NameIdentifier,
        username),

    new System.Security.Claims.Claim(
        System.Security.Claims.ClaimTypes.Name,
        username)
};

        var identity =
            new System.Security.Claims.ClaimsIdentity(
                claims,
                "SecureChatCookie");

        var principal =
            new System.Security.Claims.ClaimsPrincipal(
                identity);

        await HttpContext.SignInAsync(
            "SecureChatCookie",
            principal);

        return RedirectToAction("Index", "Chat");
    }

    public async Task<IActionResult> Logout()
    {
        var username = User.Identity?.Name;
        if (username != null) _keyCache.Remove(username);

        await HttpContext.SignOutAsync(
            "SecureChatCookie");

        return RedirectToAction("Login");
    }
}