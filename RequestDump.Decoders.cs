using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Primitives;

namespace RequestEcho;

public sealed partial class RequestDump
{
    // ================================================================== header dispatcher

    private void AnalyzeHeader(string name, string value, (string, int) key)
    {
        var lname = name.ToLowerInvariant();
        bool isAuth = lname is "authorization" or "proxy-authorization";

        if (isAuth) DescribeAuthorization(value, "  ");
        else if (lname == "www-authenticate" || lname == "proxy-authenticate") L($"  challenge: {value}");

        if (lname == "cookie") DescribeCookies(value, "  ");
        if (lname == "traceparent") DescribeTraceparent(value, "  ");
        if (lname == "x-forwarded-client-cert") DescribeXfcc(value, "  ");

        bool found = false;
        foreach (var jwt in FindJwts(value))
        {
            found = true;
            L(lname == "cookie" ? "  JWT inside cookie:" : "  JWT:");
            DescribeJwt(jwt, "    ");
        }

        if (_headerCerts.TryGetValue(key, out var certs))
        {
            found = true;
            for (int i = 0; i < certs.Count; i++)
            {
                L($"  Certificate #{i} ({certs[i].Label}):");
                DescribeCertificate(certs[i].Cert, "    ");
            }
        }

        if (!found && !isAuth && lname != "cookie" && TryBase64Json(value) is { } json)
        {
            L("  Base64-encoded JSON (e.g. X-MS-CLIENT-PRINCIPAL, X-Userinfo, X-Apigateway-Api-Userinfo):");
            L(Indent(json, "    "));
        }
    }

    // ================================================================== Authorization

    private void DescribeAuthorization(string value, string ind)
    {
        var sp = value.IndexOf(' ');
        var scheme = sp < 0 ? value : value[..sp];
        var param = sp < 0 ? "" : value[(sp + 1)..].Trim();
        L($"{ind}Scheme: {scheme}");

        switch (scheme.ToLowerInvariant())
        {
            case "basic":
            {
                L($"{ind}Basic = Base64(\"user:password\") - only encoded, NOT encrypted; protection relies on TLS.");
                byte[] raw;
                try { raw = Convert.FromBase64String(param); }
                catch { L($"{ind}! parameter is not valid Base64"); break; }
                var decoded = TryUtf8(raw, out var s) ? s : Encoding.Latin1.GetString(raw);
                var colon = decoded.IndexOf(':');
                if (colon < 0) { L($"{ind}! decoded value has no ':' -> '{decoded}'"); break; }
                L($"{ind}  user     = {decoded[..colon]}");
                var pwLen = decoded.Length - colon - 1;
                L($"{ind}  password = {decoded[(colon + 1)..]}   ({(pwLen == 0 ? "empty" : pwLen + " chars")})");
                if (!TryUtf8(raw, out _)) L($"{ind}  (not valid UTF-8, decoded as ISO-8859-1)");
                break;
            }
            case "bearer":
                if (FindJwts(param).Any())
                    L($"{ind}Bearer token is a JWT (self-contained access/id token) - decoded below.");
                else
                    L($"{ind}Opaque bearer token ({param.Length} chars) - reference token, needs introspection at the issuer.");
                break;

            case "dpop":
                L($"{ind}DPoP-bound access token (RFC 9449) - the proof of possession is in the 'DPoP' header (a JWT).");
                break;

            case "digest":
                L($"{ind}HTTP Digest (RFC 7616) parameters:");
                foreach (var (k, v) in ParseAuthParams(param)) L($"{ind}  {k,-10} = {v}");
                break;

            case "aws4-hmac-sha256":
                L($"{ind}AWS Signature Version 4:");
                foreach (var part in param.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
                {
                    L($"{ind}  {part}");
                    if (part.StartsWith("Credential=", StringComparison.Ordinal))
                    {
                        var c = part["Credential=".Length..].Split('/');
                        if (c.Length >= 5)
                            L($"{ind}    -> access key {c[0]}, date {c[1]}, region {c[2]}, service {c[3]}");
                    }
                }
                break;

            case "negotiate":
            case "ntlm":
            {
                byte[] raw;
                try { raw = Convert.FromBase64String(param); }
                catch { L($"{ind}! token is not valid Base64"); break; }
                DescribeNegotiateToken(raw, ind);
                break;
            }

            case "sharedkey":
            case "sharedkeylite":
                L($"{ind}Azure Storage shared key: account:signature = {param}");
                break;

            default:
                L($"{ind}Unknown / proprietary scheme, parameter: {Truncate(param, 200)}");
                break;
        }
    }

    private void DescribeNegotiateToken(byte[] b, string ind)
    {
        var ntlmAt = IndexOf(b, "NTLMSSP\0"u8);
        if (b.Length > 0 && b[0] == 0x60)
        {
            L($"{ind}GSS-API initial context token (SPNEGO, RFC 4178). Mechanisms referenced:");
            if (IndexOf(b, [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x12, 0x01, 0x02, 0x02]) >= 0) L($"{ind}  - Kerberos V5 (1.2.840.113554.1.2.2)");
            if (IndexOf(b, [0x06, 0x09, 0x2A, 0x86, 0x48, 0x82, 0xF7, 0x12, 0x01, 0x02, 0x02]) >= 0) L($"{ind}  - MS Kerberos (1.2.840.48018.1.2.2)");
            if (IndexOf(b, [0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0A]) >= 0) L($"{ind}  - NTLM (1.3.6.1.4.1.311.2.2.10)");
            if (ntlmAt < 0 && IndexOf(b, [0x6E]) >= 0)
            {
                var strings = PrintableStrings(b, 3).Take(12).ToList();
                if (strings.Count > 0)
                    L($"{ind}  Kerberos AP-REQ - readable strings (realm / service principal name): {string.Join(", ", strings)}");
            }
        }
        else if (b.Length > 0 && b[0] == 0xA1)
        {
            L($"{ind}SPNEGO negTokenResp (continuation / mutual authentication response).");
        }

        if (ntlmAt >= 0) DescribeNtlm(b.AsSpan(ntlmAt).ToArray(), ind);
        else if (b.Length > 0 && b[0] != 0x60 && b[0] != 0xA1) L($"{ind}Unrecognised token ({b.Length} bytes).");
    }

    private void DescribeNtlm(byte[] b, string ind)
    {
        if (b.Length < 12) { L($"{ind}NTLM: truncated message"); return; }
        int type = BitConverter.ToInt32(b, 8);
        L($"{ind}NTLM message type {type}: " + type switch
        {
            1 => "NEGOTIATE (client -> server, step 1)",
            2 => "CHALLENGE (server -> client, step 2)",
            3 => "AUTHENTICATE (client -> server, step 3)",
            _ => "unknown"
        });
        if (type == 1 && b.Length >= 16)
            L($"{ind}  flags 0x{BitConverter.ToUInt32(b, 12):X8}");
        if (type == 3 && b.Length >= 64)
        {
            uint flags = BitConverter.ToUInt32(b, 60);
            bool unicode = (flags & 1) != 0;
            string Field(int off)
            {
                int len = BitConverter.ToUInt16(b, off);
                int pos = BitConverter.ToInt32(b, off + 4);
                if (len == 0) return "(empty)";
                if (pos < 0 || pos + len > b.Length) return "(out of range)";
                return unicode ? Encoding.Unicode.GetString(b, pos, len) : Encoding.ASCII.GetString(b, pos, len);
            }
            int ntLen = BitConverter.ToUInt16(b, 20);
            L($"{ind}  domain      = {Field(28)}");
            L($"{ind}  user        = {Field(36)}");
            L($"{ind}  workstation = {Field(44)}");
            L($"{ind}  NT response = {ntLen} bytes -> {(ntLen > 24 ? "NTLMv2" : ntLen == 24 ? "NTLMv1 (weak!)" : "anonymous/none")}");
        }
    }

    private void DescribeCookies(string value, string ind)
    {
        foreach (var part in value.Split(';', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
        {
            var eq = part.IndexOf('=');
            var n = eq < 0 ? part : part[..eq];
            var v = eq < 0 ? "" : part[(eq + 1)..];
            L($"{ind}cookie {n} = {Truncate(v, 120)}{(v.Length > 120 ? $"  ({v.Length} chars)" : "")}");
        }
    }

    private void DescribeTraceparent(string value, string ind)
    {
        var p = value.Trim().Split('-');
        if (p.Length != 4) { L($"{ind}! not a valid W3C traceparent"); return; }
        L($"{ind}W3C Trace Context: version {p[0]}, trace-id {p[1]}, parent span-id {p[2]}, flags {p[3]}" +
          (byte.TryParse(p[3], System.Globalization.NumberStyles.HexNumber, null, out var f) ? ((f & 1) == 1 ? " (sampled)" : " (not sampled)") : ""));
    }

    private void DescribeXfcc(string value, string ind)
    {
        L($"{ind}Envoy / Istio x-forwarded-client-cert (one element per hop):");
        int i = 0;
        foreach (var element in SplitOutsideQuotes(value, ','))
        {
            L($"{ind}  element {i++}:");
            foreach (var pair in SplitOutsideQuotes(element, ';'))
            {
                var eq = pair.IndexOf('=');
                if (eq < 0) continue;
                var k = pair[..eq].Trim();
                var v = pair[(eq + 1)..].Trim().Trim('"');
                if (k.Equals("Cert", StringComparison.OrdinalIgnoreCase) || k.Equals("Chain", StringComparison.OrdinalIgnoreCase))
                    v = $"<URL-encoded PEM, {v.Length} chars - decoded below>";
                L($"{ind}    {k,-8} = {v}");
            }
        }
    }

    // ================================================================== JWT

    private static readonly Regex JwtRx = new(
        @"eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*(?:\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*)?",
        RegexOptions.Compiled);

    private static IEnumerable<string> FindJwts(string text) =>
        JwtRx.Matches(text).Select(m => m.Value).Where(t => TryB64UrlJson(t.Split('.')[0]) != null).Distinct();

    private static readonly Dictionary<string, string> ClaimInfo = new()
    {
        ["iss"] = "issuer", ["sub"] = "subject", ["aud"] = "audience", ["exp"] = "expires",
        ["nbf"] = "not before", ["iat"] = "issued at", ["jti"] = "token id", ["azp"] = "authorized party (client)",
        ["client_id"] = "OAuth client", ["scope"] = "scopes", ["scp"] = "scopes", ["roles"] = "roles",
        ["auth_time"] = "user authenticated at", ["nonce"] = "OIDC nonce", ["acr"] = "authn context class",
        ["amr"] = "authn methods", ["sid"] = "session id", ["at_hash"] = "access token hash",
        ["c_hash"] = "code hash", ["cnf"] = "confirmation / proof-of-possession key (RFC 7800/8705)",
        ["tid"] = "Entra ID tenant", ["oid"] = "Entra ID object id", ["upn"] = "user principal name",
        ["preferred_username"] = "user name", ["email"] = "e-mail", ["name"] = "display name",
        ["groups"] = "groups", ["appid"] = "Entra ID application id", ["ver"] = "token version",
        ["idp"] = "identity provider", ["typ"] = "token type", ["realm_access"] = "Keycloak realm roles",
        ["resource_access"] = "Keycloak client roles", ["updated_at"] = "profile updated at",
        ["act"] = "actor (token exchange, RFC 8693)", ["may_act"] = "allowed actor (RFC 8693)",
    };

    private static readonly HashSet<string> TimeClaims = ["exp", "nbf", "iat", "auth_time", "updated_at"];

    private void DescribeJwt(string token, string ind)
    {
        var parts = token.Split('.');
        var header = TryB64UrlJson(parts[0]);
        if (header == null) { L($"{ind}! header is not Base64url JSON"); return; }

        string? alg = null;
        using (var hd = JsonDocument.Parse(header))
            if (hd.RootElement.TryGetProperty("alg", out var a) && a.ValueKind == JsonValueKind.String) alg = a.GetString();

        if (parts.Length == 5)
        {
            L($"{ind}JWE (encrypted token, {token.Length} chars) - content cannot be read without the key.");
            L($"{ind}Header : {Compact(header)}");
            return;
        }

        L($"{ind}JWS/JWT, {token.Length} chars - signature NOT validated");
        L($"{ind}Header : {Compact(header)}");
        if (string.Equals(alg, "none", StringComparison.OrdinalIgnoreCase))
            L($"{ind}         ! alg=none -> unsigned token, must never be accepted");
        else if (alg?.StartsWith("HS", StringComparison.Ordinal) == true)
            L($"{ind}         alg {alg} = symmetric (shared secret) signature");
        else if (alg != null)
            L($"{ind}         alg {alg} = asymmetric signature, verify with issuer key (kid/jwks_uri)");

        var payloadJson = TryB64UrlJson(parts[1]);
        if (payloadJson == null)
        {
            L($"{ind}Payload: not JSON ({parts[1].Length} chars)");
        }
        else
        {
            using var pd = JsonDocument.Parse(payloadJson);
            var root = pd.RootElement;
            if (root.ValueKind != JsonValueKind.Object) { L($"{ind}Payload: {Compact(payloadJson)}"); }
            else
            {
                L($"{ind}Claims :");
                var now = DateTimeOffset.UtcNow;
                foreach (var p in root.EnumerateObject())
                {
                    var raw = Truncate(p.Value.GetRawText(), 300);
                    var line = $"{ind}  {p.Name,-20} = {raw}";
                    if (TimeClaims.Contains(p.Name) && p.Value.TryGetDouble(out var secs))
                    {
                        var t = DateTimeOffset.FromUnixTimeSeconds((long)secs);
                        line += $"   -> {t:yyyy-MM-dd HH:mm:ss} UTC ({Rel(t)})";
                    }
                    if (ClaimInfo.TryGetValue(p.Name, out var info)) line += $"   [{info}]";
                    L(line);
                }

                // validity summary
                var status = new List<string>();
                if (root.TryGetProperty("exp", out var exp) && exp.TryGetDouble(out var e))
                    status.Add(DateTimeOffset.FromUnixTimeSeconds((long)e) < now ? "EXPIRED" : "not expired");
                if (root.TryGetProperty("nbf", out var nbf) && nbf.TryGetDouble(out var n) && DateTimeOffset.FromUnixTimeSeconds((long)n) > now)
                    status.Add("NOT YET VALID (nbf in the future - clock skew?)");
                if (status.Count > 0) L($"{ind}Time check: {string.Join(", ", status)} (server clock {now:HH:mm:ss} UTC)");

                // certificate binding (RFC 8705 mTLS-bound access token)
                if (root.TryGetProperty("cnf", out var cnf) && cnf.ValueKind == JsonValueKind.Object &&
                    cnf.TryGetProperty("x5t#S256", out var x5t) && x5t.ValueKind == JsonValueKind.String)
                {
                    var want = x5t.GetString();
                    var match = _allCerts.FirstOrDefault(c => Base64Url(c.Cert.GetCertHash(HashAlgorithmName.SHA256)) == want);
                    L(match.Cert != null
                        ? $"{ind}cnf x5t#S256 MATCHES the client certificate from: {match.Source}"
                        : $"{ind}cnf x5t#S256 does NOT match any client certificate seen in this request ({_allCerts.Count} seen)");
                }
            }
        }

        var sig = parts.Length > 2 ? B64UrlDecode(parts[2]) : null;
        L($"{ind}Signature: {(sig == null || sig.Length == 0 ? "(empty)" : $"{sig.Length} bytes")}");
    }

    // ================================================================== certificates

    private static readonly Regex PemRx = new(
        @"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", RegexOptions.Singleline | RegexOptions.Compiled);
    private static readonly Regex Rfc9440Rx = new(@":([A-Za-z0-9+/=]{100,}):", RegexOptions.Compiled);
    private static readonly Regex Base64Rx = new(@"^[A-Za-z0-9+/]+={0,2}$", RegexOptions.Compiled);

    private void CollectHeaderCertificates()
    {
        foreach (var h in Req.Headers)
        {
            var lname = h.Key.ToLowerInvariant();
            if (lname is "authorization" or "proxy-authorization" or "cookie") continue;
            int idx = 0;
            foreach (var v in h.Value)
            {
                var certs = ExtractCertificates(v ?? "");
                if (certs.Count > 0)
                {
                    _headerCerts[(h.Key, idx)] = certs;
                    foreach (var c in certs) _allCerts.Add(($"header {h.Key}", c.Cert));
                }
                idx++;
            }
        }
    }

    private static List<(string Label, X509Certificate2 Cert)> ExtractCertificates(string value)
    {
        var result = new List<(string, X509Certificate2)>();
        if (value.Length < 100) return result;

        // 1) PEM – raw or URL-encoded (nginx $ssl_client_escaped_cert, Envoy XFCC, AWS ALB, HAProxy ...)
        var decoded = SafeUrlDecode(value);
        foreach (var (candidate, label) in new[] { (value, "PEM"), (decoded, "URL-encoded PEM") })
        {
            if (!candidate.Contains("BEGIN CERTIFICATE", StringComparison.Ordinal)) continue;
            foreach (Match m in PemRx.Matches(candidate))
            {
                var b64 = Regex.Replace(m.Groups[1].Value, "[^A-Za-z0-9+/=]", "");
                if (TryLoadCert(b64, out var c)) result.Add((label, c!));
            }
            if (result.Count > 0) return result;
        }

        // 2) RFC 9440 Client-Cert / Client-Cert-Chain (structured field byte sequence :base64:)
        foreach (Match m in Rfc9440Rx.Matches(value))
            if (TryLoadCert(m.Groups[1].Value, out var c)) result.Add(("RFC 9440 byte sequence", c!));
        if (result.Count > 0) return result;

        // 3) bare Base64 DER, possibly comma separated (IIS ARR X-ARR-ClientCert, Traefik, F5 ...)
        foreach (var candidate in new[] { value, decoded }.Distinct())
        {
            foreach (var part in candidate.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
            {
                var p = Regex.Replace(part.Trim('"'), @"\s", "");
                if (p.Length >= 200 && Base64Rx.IsMatch(p) && TryLoadCert(p, out var c)) result.Add(("Base64 DER", c!));
            }
            if (result.Count > 0) return result;
        }
        return result;
    }

    private static bool TryLoadCert(string base64, out X509Certificate2? cert)
    {
        cert = null;
        try
        {
            var der = Convert.FromBase64String(base64);
            if (der.Length < 100 || der[0] != 0x30) return false;
            cert = X509CertificateLoader.LoadCertificate(der);
            return true;
        }
        catch { return false; }
    }

    private void DescribeCertificate(X509Certificate2 c, string ind)
    {
        var now = DateTime.UtcNow;
        var nb = c.NotBefore.ToUniversalTime();
        var na = c.NotAfter.ToUniversalTime();
        var validity = now < nb ? "NOT YET VALID" : now > na ? "EXPIRED" : $"valid, expires {Rel(new DateTimeOffset(na))}";
        bool selfSigned = c.SubjectName.RawData.AsSpan().SequenceEqual(c.IssuerName.RawData);
        var sha256 = c.GetCertHash(HashAlgorithmName.SHA256);

        L($"{ind}Subject       : {c.Subject}");
        L($"{ind}Issuer        : {c.Issuer}{(selfSigned ? "   (self-signed: issuer = subject)" : "")}");
        L($"{ind}Serial        : {c.SerialNumber}");
        L($"{ind}Validity      : {nb:yyyy-MM-dd HH:mm:ss} .. {na:yyyy-MM-dd HH:mm:ss} UTC  [{validity}]");
        L($"{ind}SHA-1         : {c.Thumbprint}");
        L($"{ind}SHA-256       : {Convert.ToHexString(sha256)}");
        L($"{ind}x5t#S256      : {Base64Url(sha256)}   (value for RFC 8705 certificate-bound tokens)");
        L($"{ind}Public key    : {KeyInfo(c)}");
        L($"{ind}Signature alg : {c.SignatureAlgorithm.FriendlyName ?? c.SignatureAlgorithm.Value}");
        foreach (var ext in c.Extensions)
        {
            var name = ext.Oid?.FriendlyName ?? ext.Oid?.Value ?? "?";
            var text = string.Join("; ", ext.Format(true).Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
            L($"{ind}  ext {name}{(ext.Critical ? " [critical]" : "")}: {Truncate(text, 400)}");
        }

        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.DisableCertificateDownloads = true;
        bool ok;
        try { ok = chain.Build(c); }
        catch (Exception ex) { L($"{ind}Chain build failed: {ex.Message}"); return; }
        L($"{ind}Chain (this server's trust store, no revocation check): {(ok ? "TRUSTED" : "NOT TRUSTED")}");
        foreach (var el in chain.ChainElements) L($"{ind}  -> {el.Certificate.Subject}");
        if (!ok)
            foreach (var s in chain.ChainStatus.DistinctBy(s => s.Status))
                L($"{ind}  ! {s.Status}: {s.StatusInformation.Trim()}");

        if (overrides.Pem) L(Indent(c.ExportCertificatePem(), ind));
    }

    private static string KeyInfo(X509Certificate2 c)
    {
        var alg = c.PublicKey.Oid.FriendlyName ?? c.PublicKey.Oid.Value ?? "?";
        try
        {
            using var rsa = c.GetRSAPublicKey();
            if (rsa != null) return $"{alg} {rsa.KeySize} bit";
            using var ec = c.GetECDsaPublicKey();
            if (ec != null) return $"{alg} {ec.KeySize} bit";
        }
        catch { /* ignore */ }
        return alg;
    }

    // ================================================================== IP / forwarding helpers

    private static readonly Dictionary<string, string> KnownForwardingHeaders = new(StringComparer.OrdinalIgnoreCase)
    {
        ["X-Real-IP"] = "client IP as set by nginx/others (single value)",
        ["X-Original-Forwarded-For"] = "XFF before it was rewritten (ingress-nginx)",
        ["X-Original-For"] = "original RemoteIp saved by ASP.NET Core ForwardedHeadersMiddleware upstream",
        ["X-Original-Proto"] = "original scheme saved by ASP.NET Core ForwardedHeadersMiddleware upstream",
        ["X-Original-Host"] = "original host saved by ASP.NET Core ForwardedHeadersMiddleware / proxies",
        ["X-Original-URL"] = "original URL before rewrite (IIS ARR / Azure)",
        ["X-Original-URI"] = "original URI before rewrite (nginx)",
        ["X-Rewrite-URL"] = "original URL before rewrite",
        ["X-Forwarded-Ssl"] = "on = client used TLS at the proxy",
        ["Front-End-Https"] = "on = client used TLS at the proxy (Microsoft)",
        ["X-ARR-SSL"] = "IIS ARR / Azure App Service: TLS details of the front end",
        ["X-ARR-LOG-ID"] = "IIS ARR / Azure App Service request id",
        ["X-AppService-Proto"] = "Azure App Service: client scheme",
        ["X-Client-IP"] = "client IP (Azure App Service / various)",
        ["X-Client-Port"] = "client port (Azure App Service)",
        ["X-Azure-ClientIP"] = "Azure Front Door: client IP",
        ["X-Azure-SocketIP"] = "Azure Front Door: socket IP of the TCP connection",
        ["X-Azure-Ref"] = "Azure Front Door request reference",
        ["X-FD-HealthProbe"] = "Azure Front Door health probe",
        ["X-AppGW-Trace-Id"] = "Azure Application Gateway trace id",
        ["X-Original-Host-Port"] = "original host:port",
        ["CF-Connecting-IP"] = "Cloudflare: client IP",
        ["CF-IPCountry"] = "Cloudflare: client country",
        ["CF-Ray"] = "Cloudflare request id",
        ["CF-Visitor"] = "Cloudflare: client scheme",
        ["True-Client-IP"] = "Akamai / Cloudflare Enterprise: client IP",
        ["Fastly-Client-IP"] = "Fastly: client IP",
        ["X-Cluster-Client-IP"] = "client IP (Rackspace, Riverbed ...)",
        ["X-Envoy-External-Address"] = "Envoy: trusted external client address",
        ["X-Envoy-Internal"] = "Envoy: request is internal",
        ["X-Request-Id"] = "request correlation id",
        ["X-Correlation-Id"] = "request correlation id",
        ["X-Amzn-Trace-Id"] = "AWS ALB trace id",
        ["X-Request-Start"] = "time the proxy received the request",
        ["X-Proxy-Id"] = "proxy identifier",
        ["X-BlueCoat-Via"] = "BlueCoat proxy",
        ["X-ProxyUser-Ip"] = "Google Cloud: client IP",
        ["X-Cloud-Trace-Context"] = "Google Cloud trace context",
        ["X-Forwarded-Client-Cert"] = "Envoy/Istio: client certificate info (decoded below)",
        ["Client-Cert"] = "RFC 9440: client certificate from TLS terminating proxy (decoded below)",
        ["Client-Cert-Chain"] = "RFC 9440: client certificate chain (decoded below)",
        ["X-ARR-ClientCert"] = "IIS ARR / Azure App Service: client certificate, Base64 DER (decoded below)",
        ["X-Amzn-Mtls-Clientcert"] = "AWS ALB mTLS: client certificate, URL-encoded PEM (decoded below)",
        ["X-Amzn-Mtls-Clientcert-Leaf"] = "AWS ALB mTLS: leaf certificate (decoded below)",
    };

    private static readonly string[] TlsMetaPrefixes =
        ["X-SSL", "SSL-Client", "X-Client-Cert", "X-Client-Verify", "X-Client-DN", "X-Client-Subject", "X-Forwarded-Tls", "X-Tls-", "X-Amzn-Mtls"];

    private static string FormatEndpoint(IPAddress? ip, int port)
    {
        if (ip == null) return "(unknown)";
        return ip.AddressFamily == AddressFamily.InterNetworkV6 ? $"[{ip}]:{port}" : $"{ip}:{port}";
    }

    private static string Classify(IPAddress? ip)
    {
        if (ip == null) return "unknown";
        if (ip.IsIPv4MappedToIPv6) { var v4 = ip.MapToIPv4(); return $"IPv4-mapped IPv6 of {v4}, {Classify(v4)}"; }
        if (IPAddress.IsLoopback(ip)) return "loopback";
        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = ip.GetAddressBytes();
            return b[0] switch
            {
                10 => "private, RFC 1918",
                172 when b[1] is >= 16 and <= 31 => "private, RFC 1918",
                192 when b[1] == 168 => "private, RFC 1918",
                100 when b[1] is >= 64 and <= 127 => "carrier-grade NAT, RFC 6598",
                169 when b[1] == 254 => "link-local",
                0 => "unspecified",
                192 when b[1] == 0 && b[2] == 2 => "documentation (TEST-NET-1)",
                198 when b[1] == 51 && b[2] == 100 => "documentation (TEST-NET-2)",
                203 when b[1] == 0 && b[2] == 113 => "documentation (TEST-NET-3)",
                198 when b[1] is 18 or 19 => "benchmarking, RFC 2544",
                >= 224 and <= 239 => "multicast",
                >= 240 => "reserved",
                _ => "public"
            };
        }
        if (ip.Equals(IPAddress.IPv6Any)) return "unspecified";
        if (ip.IsIPv6LinkLocal) return "link-local";
        if (ip.IsIPv6UniqueLocal) return "unique local (fc00::/7, private)";
        if (ip.IsIPv6SiteLocal) return "site-local (deprecated)";
        if (ip.IsIPv6Multicast) return "multicast";
        if (ip.IsIPv6Teredo) return "Teredo tunnel";
        var v6 = ip.GetAddressBytes();
        if (v6[0] == 0x20 && v6[1] == 0x01 && v6[2] == 0x0d && v6[3] == 0xb8) return "documentation (2001:db8::/32)";
        return "global unicast (public)";
    }

    /// <summary>Describes a node from XFF / Forwarded: "1.2.3.4", "1.2.3.4:5678", "[::1]:80", "unknown", "_hidden".</summary>
    private static string DescribeNode(string raw)
    {
        var s = raw.Trim().Trim('"');
        if (s.Equals("unknown", StringComparison.OrdinalIgnoreCase)) return "(unknown - proxy did not reveal it)";
        if (s.StartsWith('_')) return "(obfuscated identifier, RFC 7239)";

        string host = s; string? port = null;
        if (s.StartsWith('['))
        {
            var end = s.IndexOf(']');
            if (end > 0) { host = s[1..end]; if (end + 2 < s.Length && s[end + 1] == ':') port = s[(end + 2)..]; }
        }
        else if (s.Count(ch => ch == ':') == 1)
        {
            var i = s.IndexOf(':'); host = s[..i]; port = s[(i + 1)..];
        }

        return IPAddress.TryParse(host, out var ip)
            ? $"[{Classify(ip)}{(port != null ? ", port " + port : "")}]"
            : "[not an IP address]";
    }

    private static List<string> SplitList(StringValues values) =>
        values.SelectMany(v => (v ?? "").Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)).ToList();

    private static List<string> SplitOutsideQuotes(string s, char sep)
    {
        var list = new List<string>();
        var sb = new StringBuilder();
        bool quoted = false;
        for (int i = 0; i < s.Length; i++)
        {
            var ch = s[i];
            if (ch == '\\' && quoted && i + 1 < s.Length) { sb.Append(ch).Append(s[++i]); continue; }
            if (ch == '"') quoted = !quoted;
            if (ch == sep && !quoted) { if (sb.ToString().Trim().Length > 0) list.Add(sb.ToString().Trim()); sb.Clear(); continue; }
            sb.Append(ch);
        }
        if (sb.ToString().Trim().Length > 0) list.Add(sb.ToString().Trim());
        return list;
    }

    private static Dictionary<string, string> ParseForwardedElement(string element)
    {
        var d = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var pair in SplitOutsideQuotes(element, ';'))
        {
            var eq = pair.IndexOf('=');
            if (eq > 0) d[pair[..eq].Trim().ToLowerInvariant()] = pair[(eq + 1)..].Trim().Trim('"');
        }
        return d;
    }

    private static IEnumerable<(string Key, string Value)> ParseAuthParams(string s) =>
        SplitOutsideQuotes(s, ',').Select(p =>
        {
            var eq = p.IndexOf('=');
            return eq < 0 ? (p, "") : (p[..eq].Trim(), p[(eq + 1)..].Trim().Trim('"'));
        });

    // ================================================================== generic helpers

    private static readonly JsonSerializerOptions PrettyOptions = new()
    {
        WriteIndented = true,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    private static readonly JsonSerializerOptions CompactOptions = new()
    {
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    private static string? PrettyJson(string s)
    {
        try { using var d = JsonDocument.Parse(s); return JsonSerializer.Serialize(d.RootElement, PrettyOptions); }
        catch { return null; }
    }

    private static string Compact(string json)
    {
        try { using var d = JsonDocument.Parse(json); return JsonSerializer.Serialize(d.RootElement, CompactOptions); }
        catch { return json; }
    }

    private static string? TryB64UrlJson(string part)
    {
        var bytes = B64UrlDecode(part);
        if (bytes == null || !TryUtf8(bytes, out var s)) return null;
        s = s.Trim();
        if (!(s.StartsWith('{') || s.StartsWith('['))) return null;
        try { using var _ = JsonDocument.Parse(s); return s; } catch { return null; }
    }

    private static string? TryBase64Json(string value)
    {
        var v = value.Trim();
        if (v.Length < 16 || !Regex.IsMatch(v, @"^[A-Za-z0-9+/_-]+={0,2}$")) return null;
        var json = TryB64UrlJson(v.TrimEnd('='));
        return json == null ? null : PrettyJson(json);
    }

    private static byte[]? B64UrlDecode(string s)
    {
        s = s.Replace('-', '+').Replace('_', '/');
        switch (s.Length % 4)
        {
            case 1: return null;
            case 2: s += "=="; break;
            case 3: s += "="; break;
        }
        try { return Convert.FromBase64String(s); } catch { return null; }
    }

    private static string Base64Url(byte[] b) =>
        Convert.ToBase64String(b).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    private static bool TryUtf8(byte[] b, out string s)
    {
        try { s = StrictUtf8.GetString(b); return true; }
        catch { s = ""; return false; }
    }

    private static bool TryGetText(byte[] b, out string text)
    {
        if (!TryUtf8(b, out text)) return false;
        foreach (var ch in text)
            if (char.IsControl(ch) && ch is not ('\r' or '\n' or '\t')) return false;
        return true;
    }

    private static string SafeUrlDecode(string s)
    {
        try { return Uri.UnescapeDataString(s); } catch { return s; }
    }

    private static string Indent(string text, string ind) =>
        string.Join("\n", text.Replace("\r\n", "\n").TrimEnd('\n').Split('\n').Select(l => ind + l));

    private static string EscapeControl(string s) =>
        s.Any(char.IsControl)
            ? string.Concat(s.Select(ch => char.IsControl(ch) ? $"\\x{(int)ch:x2}" : ch.ToString()))
            : s;

    private static string Truncate(string s, int max) => s.Length <= max ? s : s[..max] + "...";

    private static string Rel(DateTimeOffset t)
    {
        var d = t - DateTimeOffset.UtcNow;
        var a = d.Duration();
        var s = a.TotalSeconds < 90 ? $"{a.TotalSeconds:0} s"
              : a.TotalMinutes < 90 ? $"{a.TotalMinutes:0} min"
              : a.TotalHours < 48 ? $"{a.TotalHours:0.#} h"
              : $"{a.TotalDays:0.#} days";
        return d >= TimeSpan.Zero ? $"in {s}" : $"{s} ago";
    }

    private static int IndexOf(byte[] haystack, ReadOnlySpan<byte> needle) => haystack.AsSpan().IndexOf(needle);

    /// <summary>
    /// Extracts ASN.1 GeneralString values (tag 0x1B) – in a Kerberos AP-REQ these are the
    /// unencrypted realm and service principal name parts of the ticket.
    /// </summary>
    private static IEnumerable<string> PrintableStrings(byte[] b, int minLen)
    {
        var seen = new HashSet<string>();
        for (int i = 0; i + 2 < b.Length; i++)
        {
            if (b[i] != 0x1B) continue;
            int len = b[i + 1];
            if (len < minLen || len > 127 || i + 2 + len > b.Length) continue;
            var span = b.AsSpan(i + 2, len);
            bool printable = true;
            foreach (var x in span) if (x is < 0x20 or > 0x7E) { printable = false; break; }
            if (!printable) continue;
            var s = Encoding.ASCII.GetString(span);
            if (seen.Add(s)) yield return s;
        }
    }

    private void HexDump(byte[] data, int max)
    {
        int len = Math.Min(data.Length, max);
        for (int off = 0; off < len; off += 16)
        {
            var hex = new StringBuilder();
            var asc = new StringBuilder();
            for (int i = 0; i < 16; i++)
            {
                if (off + i < len)
                {
                    var x = data[off + i];
                    hex.Append(x.ToString("x2")).Append(' ');
                    asc.Append(x is >= 0x20 and < 0x7F ? (char)x : '.');
                }
                else hex.Append("   ");
                if (i == 7) hex.Append(' ');
            }
            L($"  {off:x8}  {hex} |{asc}|");
        }
        if (data.Length > max) L($"  ... {data.Length - max} more bytes");
    }
}
