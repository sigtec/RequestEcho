using System.Text;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using RequestEcho;

Console.OutputEncoding = Encoding.UTF8;

var builder = WebApplication.CreateBuilder(args);

WireLog.Enabled = builder.Configuration.GetValue("Echo:WireLog", true);
WireLog.MaxBytesPerChunk = builder.Configuration.GetValue("Echo:WireLogMaxBytes", 64 * 1024);

// Server certificate from the Windows certificate store (default LocalMachine\My), used for every
// HTTPS endpoint without its own Certificate config, unless Kestrel:Certificates:Default is set.
var httpsWithoutCertificate = ServerCertificatePicker.EndpointsWithoutCertificate(builder.Configuration);
var storeCertificate = httpsWithoutCertificate.Count > 0
    ? ServerCertificatePicker.Pick(builder.Configuration.GetSection("Echo:ServerCertificate"))
    : null;

// No certificate at all (none configured, none in the store, no dev certificate):
// drop those HTTPS endpoints instead of failing at startup, so at least HTTP comes up.
IConfiguration kestrelConfig = builder.Configuration.GetSection("Kestrel");
if (httpsWithoutCertificate.Count > 0 && storeCertificate is null)
{
    if (ServerCertificatePicker.HasDevCertificate())
    {
        Console.WriteLine("Server certificate: using the ASP.NET Core development certificate.");
    }
    else
    {
        Console.WriteLine($"Server certificate: none available - HTTPS endpoint(s) disabled: {string.Join(", ", httpsWithoutCertificate)}");
        var skipped = httpsWithoutCertificate.Select(name => $"Endpoints:{name}").ToList();
        var remaining = kestrelConfig.AsEnumerable(makePathsRelative: true)
            .Where(kv => !skipped.Any(p => kv.Key.Equals(p, StringComparison.OrdinalIgnoreCase) ||
                                           kv.Key.StartsWith(p + ":", StringComparison.OrdinalIgnoreCase)));
        kestrelConfig = new ConfigurationBuilder().AddInMemoryCollection(remaining).Build();
    }
}

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
        // Overridden by an endpoint's own "Certificate"; prevents the fallback to the dev certificate.
        if (storeCertificate is not null) https.ServerCertificate = storeCertificate;

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
    var loader = kestrel.Configure(kestrelConfig, reloadOnChange: false);
    foreach (var endpoint in kestrelConfig.GetSection("Endpoints").GetChildren())
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
