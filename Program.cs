using System.Text;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using RequestEcho;

Console.OutputEncoding = Encoding.UTF8;

var builder = WebApplication.CreateBuilder(args);

WireLog.Enabled = builder.Configuration.GetValue("Echo:WireLog", true);
WireLog.MaxBytesPerChunk = builder.Configuration.GetValue("Echo:WireLogMaxBytes", 64 * 1024);

builder.WebHost.ConfigureKestrel((context, kestrel) =>
{
    // No automatic "Server: Kestrel" header – can be set explicitly via ?_h.Server=...
    kestrel.AddServerHeader = false;

    // Accept absolute-form targets whose authority differs from the Host header
    // ("GET http://other.host/ HTTP/1.1" + "Host: echo:5080") – typical forward-proxy traffic.
    kestrel.AllowHostHeaderOverride = true;

    // Defaults for every HTTPS endpoint (endpoint settings in appsettings.json override these).
    kestrel.ConfigureHttpsDefaults(https =>
    {
        // Ask for a client certificate during the handshake, but do not require one.
        https.ClientCertificateMode = ClientCertificateMode.AllowCertificate;

        // Diagnostics endpoint: accept ANY client certificate, but remember why it would have failed.
        https.ClientCertificateValidation = (cert, chain, errors) =>
        {
            TlsValidationLog.Record(cert, chain, errors);
            return true;
        };
    });

    // Raw request/response logging for every endpoint from Kestrel:Endpoints.
    // TLS is added explicitly first, so the wire logger sees the decrypted bytes.
    var loader = kestrel.Configure(context.Configuration.GetSection("Kestrel"), reloadOnChange: false);
    foreach (var endpoint in context.Configuration.GetSection("Kestrel:Endpoints").GetChildren())
    {
        loader.Endpoint(endpoint.Key, ep =>
        {
            if (ep.IsHttps) ep.ListenOptions.UseHttps(ep.HttpsOptions);
            ep.ListenOptions.UseWireLog(ep.IsHttps);
        });
    }
});

var app = builder.Build();

// Catch-all: every method, every path.
app.Map("/{**path}", EchoEndpoint.HandleAsync);

app.Run();
