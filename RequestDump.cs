using System.Diagnostics;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.AspNetCore.Connections.Features;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.WebUtilities;

namespace RequestEcho;

/// <summary>Builds the plain-text dump. Sections live here, decoders in RequestDump.Decoders.cs.</summary>
public sealed partial class RequestDump(
    HttpContext ctx,
    byte[] body,
    long bodyTotal,
    X509Certificate2? tlsCert,
    string? tlsCertError,
    ResponseOverrides overrides)
{
    private StringBuilder _sb = new();

    /// <summary>All client certificates seen in this request (TLS + forwarded headers), for cnf matching.</summary>
    private readonly List<(string Source, X509Certificate2 Cert)> _allCerts = new();

    /// <summary>Certificates found in headers, keyed by (header name, value index).</summary>
    private readonly Dictionary<(string, int), List<(string Label, X509Certificate2 Cert)>> _headerCerts = new();

    private HttpRequest Req => ctx.Request;

    public string Build()
    {
        if (tlsCert != null) _allCerts.Add(("TLS handshake of this hop", tlsCert));
        CollectHeaderCertificates();

        Banner();
        RawRequest();
        Connection();
        Tls();
        Forwarding();
        DecodedHeaders();
        Query();
        Body();
        Response();
        L();
        return _sb.ToString();
    }

    // ------------------------------------------------------------------ output helpers

    private void L(string s = "") => _sb.AppendLine(s);

    private void Section(string title)
    {
        L();
        L(new string('=', 78));
        L("  " + title);
        L(new string('=', 78));
    }

    private string Capture(Action write)
    {
        var saved = _sb;
        _sb = new StringBuilder();
        try { write(); return _sb.ToString(); }
        finally { _sb = saved; }
    }

    // ------------------------------------------------------------------ sections

    private void Banner()
    {
        var now = DateTimeOffset.Now;
        L("RequestEcho - diagnostic echo endpoint            (append ?_help for response control)");
        L($"Received : {now.UtcDateTime:yyyy-MM-dd HH:mm:ss.fff} UTC  (server local {now:yyyy-MM-dd HH:mm:ss zzz})");
        L($"Server   : {Environment.MachineName}, pid {Environment.ProcessId}, .NET {Environment.Version}");
    }

    private void RawRequest()
    {
        Section("RAW REQUEST (as received by THIS server, reconstructed)");
        var rawTarget = ctx.Features.Get<IHttpRequestFeature>()?.RawTarget;
        if (string.IsNullOrEmpty(rawTarget)) rawTarget = Req.PathBase + Req.Path + Req.QueryString;

        L($"{Req.Method} {rawTarget} {Req.Protocol}");
        foreach (var h in Req.Headers)
            foreach (var v in h.Value)
                L($"{h.Key}: {EscapeControl(v ?? "")}");
        L();

        if (bodyTotal == 0) L("(no body)");
        else if (TryGetText(body, out var text)) L(text + (bodyTotal > body.Length ? $"\n... [truncated, {bodyTotal} bytes total]" : ""));
        else L($"[binary body, {bodyTotal} bytes - see BODY section]");

        if (!Req.Protocol.StartsWith("HTTP/1", StringComparison.Ordinal))
        {
            L();
            L($"note: {Req.Protocol} - pseudo-headers (:method, :scheme, :authority, :path) are not listed;");
            L("      the Host header shown is derived from :authority.");
        }
        L("note: repeated headers are grouped by name (Kestrel merges them); order between names is preserved.");

        if (Uri.TryCreate(rawTarget, UriKind.Absolute, out var abs) && abs.Scheme is "http" or "https")
        {
            L();
            L("note: ABSOLUTE-FORM request target (typical for clients talking to a forward proxy).");
            L("      Kestrel (AllowHostHeaderOverride) replaced the Host header with the target authority");
            L($"      '{abs.Authority}' - the Host header the client originally sent is not available.");
            if (!string.Equals(abs.Scheme, Req.Scheme, StringComparison.OrdinalIgnoreCase))
                L($"      Target scheme '{abs.Scheme}' differs from the connection scheme '{Req.Scheme}'.");
        }
    }

    private void Connection()
    {
        Section("CONNECTION (this hop)");
        var c = ctx.Connection;
        L($"Client = direct TCP peer : {FormatEndpoint(c.RemoteIpAddress, c.RemotePort)}   [{Classify(c.RemoteIpAddress)}]");
        L($"Server = local socket    : {FormatEndpoint(c.LocalIpAddress, c.LocalPort)}   [{Classify(c.LocalIpAddress)}]");
        L($"Connection id            : {c.Id}");
        L($"Request trace id         : {ctx.TraceIdentifier}   (Activity: {Activity.Current?.Id ?? "-"})");
        L($"Protocol / scheme        : {Req.Protocol} / {Req.Scheme}   (IsHttps: {Req.IsHttps})");
        L($"Host header              : {Req.Host}");
        L();
        L("The direct peer is the LAST network hop (e.g. your innermost proxy / load balancer),");
        L("not necessarily the original client - see PROXY / FORWARDING ANALYSIS.");
    }

    private void Tls()
    {
        Section("TLS (this hop)");
        var tls = ctx.Features.Get<ITlsHandshakeFeature>();
        if (tls == null)
        {
            L("No TLS on this hop (plain HTTP).");
            L("If the client used HTTPS, TLS was terminated upstream - check X-Forwarded-Proto / Forwarded");
            L("and the client certificate headers in DECODED HEADER CONTENT.");
            return;
        }

        L($"Protocol           : {tls.Protocol}");
        L($"Cipher suite       : {tls.NegotiatedCipherSuite?.ToString() ?? "(n/a)"}");
        L($"SNI host name      : {(string.IsNullOrEmpty(tls.HostName) ? "(none sent)" : tls.HostName)}");
        if (!string.IsNullOrEmpty(tls.HostName) && !string.Equals(tls.HostName, Req.Host.Host, StringComparison.OrdinalIgnoreCase))
            L($"                     ! differs from Host header '{Req.Host.Host}' (domain fronting / proxy rewriting?)");
        L();

        if (tlsCertError != null)
        {
            L($"Client certificate : ERROR while retrieving: {tlsCertError}");
        }
        else if (tlsCert == null)
        {
            L("Client certificate : none presented on this hop.");
            L("  (Kestrel requests one with ClientCertificateMode=AllowCertificate; if a proxy terminates TLS,");
            L("   the client certificate can only arrive here as a forwarded header.)");
        }
        else
        {
            L("Client certificate (from the TLS handshake):");
            DescribeCertificate(tlsCert, "  ");
            var tlsResult = TlsValidationLog.Get(tlsCert);
            if (tlsResult != null)
                L($"  TLS-layer validation : {tlsResult}  (accepted anyway - diagnostics mode)");
        }
    }

    private void Forwarding()
    {
        Section("PROXY / FORWARDING ANALYSIS");
        var h = Req.Headers;
        var c = ctx.Connection;
        var direct = FormatEndpoint(c.RemoteIpAddress, c.RemotePort);

        L($"Direct peer (last hop) : {direct}   [{Classify(c.RemoteIpAddress)}]");

        // ---- X-Forwarded-For
        var xff = SplitList(h["X-Forwarded-For"]);
        if (xff.Count > 0)
        {
            L();
            L("X-Forwarded-For (each proxy APPENDS the address of the peer it saw):");
            for (int i = 0; i < xff.Count; i++)
            {
                var role = i == 0
                    ? "original client as claimed (spoofable unless your edge proxy overwrites XFF)"
                    : $"proxy #{i} (as seen by proxy #{i + 1})";
                L($"  [{i}] {xff[i],-42} {DescribeNode(xff[i])}");
                L($"       -> {role}");
            }
            L($"  [>] {direct,-42} -> proxy #{xff.Count} = direct peer (the last proxy does not appear in XFF)");
        }

        PrintList("X-Forwarded-Proto", "[0] = scheme the client used at the outermost proxy");
        PrintList("X-Forwarded-Host", "[0] = host name the client requested");
        PrintList("X-Forwarded-Port", null);
        PrintList("X-Forwarded-Prefix", "path base removed by a proxy");
        PrintList("X-Forwarded-Server", null);

        // ---- RFC 7239 Forwarded
        var fwdElements = h["Forwarded"].SelectMany(v => SplitOutsideQuotes(v ?? "", ',')).ToList();
        if (fwdElements.Count > 0)
        {
            L();
            L("Forwarded (RFC 7239), one element per proxy hop:");
            for (int i = 0; i < fwdElements.Count; i++)
            {
                var pairs = ParseForwardedElement(fwdElements[i]);
                L($"  hop {i}: " + string.Join("  ", pairs.Select(p => $"{p.Key}={p.Value}")));
                if (pairs.TryGetValue("for", out var f)) L($"         for: {DescribeNode(f)}");
                if (pairs.TryGetValue("by", out var b)) L($"         by : {DescribeNode(b)}");
            }
        }

        // ---- Via
        var via = SplitList(h["Via"]);
        if (via.Count > 0)
        {
            L();
            L("Via (protocol + proxy per hop):");
            for (int i = 0; i < via.Count; i++) L($"  [{i}] {via[i]}");
        }

        // ---- other well known forwarding / client IP / TLS-offload headers
        var known = KnownForwardingHeaders.Where(k => h.ContainsKey(k.Key)).ToList();
        if (known.Count > 0)
        {
            L();
            L("Other proxy / CDN / load balancer headers:");
            foreach (var (name, desc) in known)
            {
                var v = h[name].ToString();
                L($"  {name}: {(v.Length > 120 ? v[..120] + "... (" + v.Length + " chars)" : v)}");
                L($"      ({desc})");
            }
        }

        var tlsMeta = h.Where(x => TlsMetaPrefixes.Any(p => x.Key.StartsWith(p, StringComparison.OrdinalIgnoreCase))).ToList();
        if (tlsMeta.Count > 0)
        {
            L();
            L("TLS offloading metadata headers (set by the TLS terminating proxy):");
            foreach (var x in tlsMeta)
            {
                var v = x.Value.ToString();
                L($"  {x.Key}: {(v.Length > 120 ? v[..120] + "... (" + v.Length + " chars, see DECODED HEADER CONTENT)" : v)}");
            }
        }

        // ---- summary
        var fwdFirst = fwdElements.Count > 0 ? ParseForwardedElement(fwdElements[0]) : new Dictionary<string, string>();
        string clientIp = fwdFirst.GetValueOrDefault("for")
                          ?? xff.FirstOrDefault()
                          ?? h["X-Real-IP"].FirstOrDefault()
                          ?? direct;
        string scheme = fwdFirst.GetValueOrDefault("proto")
                        ?? SplitList(h["X-Forwarded-Proto"]).FirstOrDefault()
                        ?? Req.Scheme;
        string host = fwdFirst.GetValueOrDefault("host")
                      ?? SplitList(h["X-Forwarded-Host"]).FirstOrDefault()
                      ?? Req.Host.ToString();

        L();
        L("Effective view IF every proxy in the chain is trusted:");
        L($"  client  : {clientIp}");
        L($"  scheme  : {scheme}");
        L($"  host    : {host}");
        L($"  path    : {SplitList(h["X-Forwarded-Prefix"]).FirstOrDefault() ?? ""}{Req.PathBase}{Req.Path}");

        L();
        L("ASP.NET Core ForwardedHeadersMiddleware with DEFAULT options (ForwardLimit = 1,");
        L("only loopback proxies trusted) would here:");
        if (xff.Count == 0)
            L("  do nothing (no X-Forwarded-For).");
        else if (c.RemoteIpAddress != null && IPAddress.IsLoopback(c.RemoteIpAddress.IsIPv4MappedToIPv6 ? c.RemoteIpAddress.MapToIPv4() : c.RemoteIpAddress))
            L($"  use the RIGHTMOST X-Forwarded-For entry '{xff.LastOrDefault()}' as RemoteIpAddress (one hop only).");
        else
            L($"  IGNORE the headers, because the direct peer {direct} is not in KnownProxies/KnownNetworks.");
        L("  For multi-hop setups configure ForwardLimit + KnownProxies/KnownNetworks explicitly.");
        if (fwdElements.Count > 0)
            L("  Note: the RFC 7239 'Forwarded' header is NOT evaluated by ForwardedHeadersMiddleware.");

        void PrintList(string name, string? note)
        {
            var list = SplitList(h[name]);
            if (list.Count == 0) return;
            L();
            L($"{name}{(note != null ? "   (" + note + ")" : "")}:");
            for (int i = 0; i < list.Count; i++) L($"  [{i}] {list[i]}");
            if (list.Count > 1) L("  (multiple values = appended by several proxies)");
        }
    }

    private void DecodedHeaders()
    {
        Section("DECODED / INTERPRETED HEADER CONTENT");
        L("(signatures are NOT validated - this is a decoding aid, not an authentication check)");

        bool any = false;
        foreach (var h in Req.Headers)
        {
            int idx = 0;
            foreach (var v in h.Value)
            {
                var value = v ?? "";
                var key = (h.Key, idx++);
                var content = Capture(() => AnalyzeHeader(h.Key, value, key));
                if (content.Length == 0) continue;
                any = true;
                L();
                L($"[{h.Key}]");
                _sb.Append(content);
            }
        }
        if (!any)
        {
            L();
            L("Nothing recognised (no Authorization, JWT, certificate, trace context, Base64-JSON ...).");
        }
    }

    private void Query()
    {
        Section("QUERY PARAMETERS (URL-decoded)");
        if (Req.Query.Count == 0) { L("(none)"); return; }
        foreach (var (k, values) in Req.Query)
            foreach (var v in values)
                L($"  {k} = {EscapeControl(v ?? "")}{(ResponseOverrides.IsControlKey(k) ? "      <- response control" : "")}");

        foreach (var (k, values) in Req.Query)
            foreach (var v in values)
                foreach (var jwt in FindJwts(v ?? ""))
                {
                    L();
                    L($"  JWT in query parameter '{k}':");
                    DescribeJwt(jwt, "    ");
                }
    }

    private void Body()
    {
        Section("BODY");
        L($"Content-Type      : {Req.ContentType ?? "(none)"}");
        L($"Content-Length    : {Req.ContentLength?.ToString() ?? "(not set - chunked or no body)"}");
        L($"Bytes received    : {bodyTotal}{(bodyTotal > body.Length ? $" (first {body.Length} captured)" : "")}");
        if (bodyTotal == 0) return;

        if (!TryGetText(body, out var text))
        {
            L();
            L("Binary content (hex dump of the first 4096 bytes):");
            HexDump(body, 4096);
            return;
        }

        var ct = Req.ContentType ?? "";
        if (ct.Contains("application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase))
        {
            L();
            L("Form fields:");
            foreach (var (k, values) in QueryHelpers.ParseQuery(text))
                foreach (var v in values) L($"  {k} = {v}");
        }
        else if (ct.Contains("json", StringComparison.OrdinalIgnoreCase) && PrettyJson(text) is { } pretty)
        {
            L();
            L("JSON (pretty):");
            L(Indent(pretty, "  "));
        }

        int n = 0;
        foreach (var jwt in FindJwts(text))
        {
            if (++n > 10) { L("  ... more JWTs omitted"); break; }
            L();
            L("JWT found in body (e.g. OIDC form_post id_token):");
            DescribeJwt(jwt, "  ");
        }
    }

    private void Response()
    {
        Section("RESPONSE (controlled via query parameters - see ?_help)");
        var res = ctx.Response;
        L($"Status : {res.StatusCode}");
        if (overrides.Log.Count > 0)
        {
            L("Overrides:");
            foreach (var l in overrides.Log) L("  " + l);
        }
        L("Headers set by the application:");
        foreach (var h in res.Headers)
            foreach (var v in h.Value)
                L($"  {h.Key}: {v}");
        L("(Kestrel adds Date and Content-Length / Transfer-Encoding when sending; proxies may add or strip more.)");
    }
}
