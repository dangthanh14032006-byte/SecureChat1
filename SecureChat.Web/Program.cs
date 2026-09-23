using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.SignalR;
using SecureChat.Core.Services;
using SecureChat.Web.Hubs;
using SecureChat.Web.Services;
using SecureChat.Core.Crypto;
using SecureChat.Web.Services;
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllersWithViews();

builder.Services.AddSignalR();
// UserStore
var userFile = Path.Combine(
    builder.Environment.ContentRootPath,
    "Data",
    "users.json"
);

builder.Services.AddSingleton<UserStore>(
    new UserStore(userFile)
);
builder.Services.AddSingleton<KeySessionCache>();

var messagesFile = Path.Combine(
    builder.Environment.ContentRootPath, "Data", "messages.json");
builder.Services.AddSingleton(new EncryptedMessageStore(messagesFile));

var groupsFile = Path.Combine(builder.Environment.ContentRootPath, "Data", "groups.json");
builder.Services.AddSingleton(new GroupStore(groupsFile));

var groupMessagesFile = Path.Combine(builder.Environment.ContentRootPath, "Data", "groupMessages.json");
builder.Services.AddSingleton(new GroupMessageStore(groupMessagesFile));
var messageFile = Path.Combine(
    builder.Environment.ContentRootPath,
    "Data",
    "messages.json"
);

builder.Services.AddSingleton<MessageStore>(
    new MessageStore(messageFile)
);
builder.Services.AddSingleton<UserPresenceService>();
builder.Services.AddSingleton<IUserIdProvider, NameUserIdProvider>();
// Authentication
builder.Services
    .AddAuthentication("SecureChatCookie")
    .AddCookie("SecureChatCookie", options =>
    {
        options.LoginPath = "/Account/Login";
    });

builder.Services.AddAuthorization();

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();

app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();

app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Account}/{action=Login}/{id?}"
);

app.MapHub<ChatHub>("/chatHub");

app.Run();