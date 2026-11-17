using System.Collections.Concurrent;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace RequestEcho;

public static class EchoEndpoint
{
    /// <summary>Maximum number of body bytes kept for display (the rest is read and discarded).</summary>
    private const int MaxBodyCapture = 1024 * 1024;

    public static async Task HandleAsync(HttpContext ctx)
    {
        var logger = ctx.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("RequestEcho");
        var config = ctx.RequestServices.GetRequiredService<IConfiguration>();
        var query = ctx.Request.Query;

        if (query.ContainsKey("_help"))
        {
            ctx.Response.ContentType = "text/plain; charset=utf-8";
            await ctx.Response.WriteAsync(HelpText.Text);
            return;
        }

        // 1) Body first – a TLS renegotiation (ClientCertificateMode.DelayCertificate) requires a consumed body.
        var (body, bodyTotal) = await ReadBodyAsync(ctx);

        // 2) Client certificate of THIS hop (null on plain HTTP or if none was sent).
        X509Certificate2? tlsCert = null;
        string? tlsCertError = null;
        try
        {
            tlsCert = await ctx.Connection.GetClientCertificateAsync(ctx.RequestAborted);
        }
        catch (Exception ex)
        {
            tlsCertError = $"{ex.GetType().Name}: {ex.Message}";
        }

        // 3) Response manipulation from query parameters.
        var overrides = ResponseOverrides.Parse(query);
        var res = ctx.Response;
        res.StatusCode = overrides.Status ?? StatusCodes.Status200OK;
        res.ContentType = "text/plain; charset=utf-8";
        res.Headers.CacheControl = "no-store";
        overrides.ApplyHeaders(res);

        // 4) Build the dump (after headers are applied, so it can show them).
        var dump = new RequestDump(ctx, body, bodyTotal, tlsCert, tlsCertError, overrides).Build();

        if (config.GetValue("Echo:LogToConsole", false))
            logger.LogInformation("Request dump:{NewLine}{Dump}", Environment.NewLine, dump);

        if (overrides.DelayMs > 0)
            await Task.Delay(overrides.DelayMs, ctx.RequestAborted);

        var responseBody = !StatusAllowsBody(res.StatusCode) || HttpMethods.IsHead(ctx.Request.Method)
            ? null
            : overrides.Body ?? dump;

        if (responseBody != null)
        {
            await res.WriteAsync(responseBody, Encoding.UTF8, ctx.RequestAborted);
            await res.CompleteAsync();
        }

        // HTTP/1.x is logged byte-exact by the connection-level wire logger;
        // HTTP/2+ is binary, so log it here in reconstructed form.
        if (!ctx.Request.Protocol.StartsWith("HTTP/1", StringComparison.Ordinal))
            WireLog.LogReconstructed(ctx, body, bodyTotal, responseBody);
    }

    private static bool StatusAllowsBody(int status) =>
        status >= 200 && status != StatusCodes.Status204NoContent && status != StatusCodes.Status304NotModified;

    private static async Task<(byte[] Data, long Total)> ReadBodyAsync(HttpContext ctx)
    {
        using var ms = new MemoryStream();
        var buffer = new byte[81920];
        long total = 0;
        int n;
        while ((n = await ctx.Request.Body.ReadAsync(buffer, ctx.RequestAborted)) > 0)
        {
            total += n;
            var room = MaxBodyCapture - (int)ms.Length;
            if (room > 0) ms.Write(buffer, 0, Math.Min(n, room));
        }
        return (ms.ToArray(), total);
    }
}

/// <summary>
/// Remembers the TLS-layer validation result per client certificate (by thumbprint),
/// because the validation callback has no access to the HttpContext.
/// </summary>
public static class TlsValidationLog
{
    private static readonly ConcurrentDictionary<string, string> Results = new();

    public static void Record(X509Certificate2 cert, X509Chain? chain, SslPolicyErrors errors)
    {
        var sb = new StringBuilder(errors == SslPolicyErrors.None ? "OK (no SslPolicyErrors)" : errors.ToString());
        if (chain != null)
            foreach (var s in chain.ChainStatus)
                sb.Append($"; {s.Status}: {s.StatusInformation.Trim()}");

        if (Results.Count > 1000) Results.Clear();
        Results[cert.Thumbprint] = sb.ToString();
    }

    public static string? Get(X509Certificate2 cert) =>
        Results.TryGetValue(cert.Thumbprint, out var v) ? v : null;
}
