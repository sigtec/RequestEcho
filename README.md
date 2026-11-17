# RequestEcho

Diagnostic echo endpoint (ASP.NET Core 10 Minimal API). Every path and every method
returns a plain-text dump of the request, including:

- raw request line, all headers, body (text, form fields, pretty JSON or hex dump)
- client IP/port (direct TCP peer), local socket, IP classification (private, CGNAT, mapped IPv6 ...)
- TLS of this hop: protocol, cipher suite, SNI, **client certificate** (details, chain, TLS validation result)
- proxy chain analysis: `X-Forwarded-*`, RFC 7239 `Forwarded`, `Via`, CDN/LB headers,
  "effective" client/scheme/host, what ASP.NET Core `ForwardedHeadersMiddleware` would do
- decoded: Basic, Bearer/JWT (claims, exp/nbf/iat, `cnf x5t#S256` vs. client cert), DPoP,
  Digest, NTLM (type 1/3: domain/user/workstation), Negotiate/Kerberos (SPNEGO, realm/SPN),
  AWS SigV4, cookies, `traceparent`, Base64-JSON headers (e.g. `X-MS-CLIENT-PRINCIPAL`)
- client certificates forwarded as headers: PEM, URL-encoded PEM (nginx, AWS ALB),
  Base64 DER (`X-ARR-ClientCert`, Traefik), RFC 9440 `Client-Cert`, Envoy `X-Forwarded-Client-Cert`

## Run

```bash
dotnet run
```

Listens on `http://0.0.0.0:5080` and `https://0.0.0.0:5443` (ASP.NET Core dev certificate,
`ClientCertificateMode=AllowCertificate`, every client certificate is accepted).
Ports/certificate are configured in `appsettings.json` (`Kestrel:Endpoints`), e.g. a real certificate:

```json
"Https": {
  "Url": "https://0.0.0.0:5443",
  "ClientCertificateMode": "AllowCertificate",
  "Certificate": { "Path": "echo.pfx", "Password": "..." }
}
```

Every HTTP method is accepted (also `TRACE`, `CONNECT`, `OPTIONS *`, WebDAV and custom verbs).
Absolute-form targets (`GET http://other.host/ HTTP/1.1`) are accepted even if the Host header
differs (`AllowHostHeaderOverride`); Kestrel then replaces the Host header with the URL authority.

`ClientCertificateMode` can also be `RequireCertificate` or `DelayCertificate`
(renegotiation, HTTP/1.1 only). `Echo:LogToConsole=true` also writes every dump to the console.

## Console output (wire log)

ASP.NET Core / Kestrel logging is switched off (`Microsoft.AspNetCore: None`); only the
startup lines remain. Instead every connection is logged **byte-exact** to the console:

- connection opened/closed (peer, local endpoint, byte counts) - shows keep-alive reuse by proxies
- `client -> server` / `server -> client` blocks exactly as on the wire, for HTTPS **after decryption**
  (incl. chunk sizes, requests Kestrel rejects with 400, and HEAD/204 responses)
- HTTP/2 is binary (frames + HPACK): those requests/responses are logged per request in
  reconstructed form (pseudo-headers, headers, body)

Settings: `Echo:WireLog` (on/off), `Echo:WireLogMaxBytes` (max bytes shown per chunk).
Only endpoints defined under `Kestrel:Endpoints` are logged (not ones from `ASPNETCORE_URLS`).

## Response control (query parameters)

| Parameter | Effect |
|---|---|
| `_status=503` | status code |
| `_h.Name=Value` | set header (repeat for multiple values) |
| `_h=Name:Value` | append header (repeatable) |
| `_rm=Name` | remove a default header (`Content-Type`, `Cache-Control`) |
| `_delay=1500` | delay in ms (max 120000) |
| `_body=text` | literal body instead of the dump |
| `_pem=1` | include PEM of all client certificates |
| `_help` | help text |

```bash
curl -k "https://localhost:5443/test?_status=302&_h.Location=https%3A%2F%2Fexample.org%2F"
```

```bash
curl -k --cert client.pem --key client.key "https://localhost:5443/api?_h.X-Test=1"
```
