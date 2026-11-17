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

Listens on `http://0.0.0.0:5080` and `https://0.0.0.0:5443` (certificate auto-selected from
LocalMachine\My, see [Server certificate](#server-certificate);
`ClientCertificateMode=AllowCertificate`, every client certificate is accepted).
Ports/certificate are configured in `appsettings.json` (`Kestrel:Endpoints`), e.g. a real certificate:

```json
"Https": {
  "Url": "https://0.0.0.0:5443",
  "ClientCertificateMode": "AllowCertificate",
  "Certificate": { "Path": "echo.pfx", "Password": "..." }
}
```

For hosting under IIS see [Running under IIS](#running-under-iis).

## Server certificate

The HTTPS certificate is determined in this order (first match wins):

1. `Kestrel:Endpoints:<Name>:Certificate`: certificate for one endpoint (file or store)
2. `Kestrel:Certificates:Default`: default for all HTTPS endpoints (file or store)
3. `Echo:ServerCertificate`: automatic selection from the Windows certificate store (see below)
4. ASP.NET Core development certificate (`dotnet dev-certs https`)
5. none: the HTTPS endpoints without a certificate are **not started**, only HTTP comes up
   (`Server certificate: none available - HTTPS endpoint(s) disabled: Https`)

An explicitly configured certificate (1., 2. or `Echo:ServerCertificate:Thumbprint`) is never skipped:
if it cannot be loaded, startup fails.

### Automatic selection from the certificate store

By default (`Echo:ServerCertificate:AutoSelect=true`) the app looks in **LocalMachine\My**
("Computer certificates > Personal") at startup and takes the best certificate:

- required: private key that this account can read, currently valid, EKU *Server Authentication*
  (or no EKU), key usage allows TLS, matches the `Subject` filter (if set)
- ranking: matches the host name/FQDN (incl. wildcard) > trusted chain > latest expiry

The candidates (`+` usable, `-` rejected with reason) and the chosen certificate are printed at startup.
If nothing fits, the dev certificate is used, or HTTPS stays off if there is none. Machine keys are often readable only by administrators
and `SYSTEM`. Run the app elevated or grant the service account read access to the private key
(certlm.msc > certificate > *All Tasks* > *Manage Private Keys...*).

| Setting | Default | Meaning |
|---|---|---|
| `Echo:ServerCertificate:AutoSelect` | `true` | enable automatic selection |
| `Echo:ServerCertificate:Location` | `LocalMachine` | `LocalMachine` or `CurrentUser` |
| `Echo:ServerCertificate:Store` | `My` | store name (`My`, `WebHosting`, ...) |
| `Echo:ServerCertificate:Subject` | | only certificates whose subject or DNS name contains this text |
| `Echo:ServerCertificate:Thumbprint` | | exactly this certificate (SHA-1 thumbprint); startup fails if it is missing or its key is not readable |

### Specifying a certificate via command line or environment variables

Every setting can be overridden on the command line (`--Section:Key=Value`) or via environment
variables (`Section__Key`, optionally with the `ASPNETCORE_` prefix). Command line wins over environment
variables, and both win over `appsettings.json`.

Certificate from the store by thumbprint:

```powershell
RequestEcho.exe --Echo:ServerCertificate:Thumbprint=F5B5BDC4F0912AA4B841A89D5BFECC1B135720E3
```

```powershell
$env:Echo__ServerCertificate__Thumbprint = "F5B5BDC4F0912AA4B841A89D5BFECC1B135720E3"
RequestEcho.exe
```

Certificate from the store by subject (auto selection limited to matching certificates):

```powershell
RequestEcho.exe --Echo:ServerCertificate:Subject=echo.example.org
```

The same via Kestrel's built-in store support (picks the valid matching certificate with the latest expiry):

```powershell
RequestEcho.exe --Kestrel:Certificates:Default:Subject=echo.example.org --Kestrel:Certificates:Default:Store=My --Kestrel:Certificates:Default:Location=LocalMachine
```

Certificate from a PFX file:

```powershell
RequestEcho.exe --Kestrel:Certificates:Default:Path=C:\certs\echo.pfx --Kestrel:Certificates:Default:Password=secret
```

```powershell
$env:Kestrel__Certificates__Default__Path = "C:\certs\echo.pfx"
$env:Kestrel__Certificates__Default__Password = "secret"
RequestEcho.exe
```

PEM certificate and key:

```bash
export Kestrel__Certificates__Default__Path=/etc/ssl/echo.crt
export Kestrel__Certificates__Default__KeyPath=/etc/ssl/echo.key
dotnet RequestEcho.dll
```

Only for the `Https` endpoint: `--Kestrel:Endpoints:Https:Certificate:Path=...` (or `Subject`/`Store`/`Location`).
To use the dev certificate instead of the store: `--Echo:ServerCertificate:AutoSelect=false`
(without a dev certificate this starts HTTP only).

## Request handling

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

## Running under IIS

Under IIS the **IIS site bindings** decide ports, host names and the HTTPS certificate.
`Kestrel:Endpoints`, `Echo:ServerCertificate` and the certificate fallback described above have
no effect. How much of the request the echo can still see depends on the hosting model:

| | `inprocess` (default, recommended) | `outofprocess` |
|---|---|---|
| Server | IIS itself (no Kestrel) | Kestrel on a random `127.0.0.1` port, IIS forwards |
| Bindings / TLS | IIS / http.sys | IIS / http.sys (the port is set by the ASP.NET Core Module, `Kestrel:Endpoints` is overridden) |
| Wire log | **not available** (Kestrel only) | only the plain-text hop IIS -> Kestrel |
| "direct TCP peer" | real client | rewritten from `X-Forwarded-For` by the IIS integration (original header moves to `X-Original-For`); the real peer is `127.0.0.1` |
| TLS details (protocol, cipher) | yes | no (only `X-Forwarded-Proto`) |
| Client certificate | yes | only as header `MS-ASPNETCORE-CLIENTCERT` (not decoded by the echo yet) |

### Setup

1. Install the **.NET 10 Hosting Bundle** on the server, then run `iisreset`.
2. Create an application pool with *.NET CLR version* = **No Managed Code**.
3. Publish and point the site to the output folder:
   ```powershell
   dotnet publish -c Release -o C:\inetpub\RequestEcho
   ```
4. Add the bindings (http/https, host name, certificate) to the site in IIS Manager.

A `web.config` placed in the project folder is taken over (and completed) by `dotnet publish`.
Suggested content:

```xml
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <location path="." inheritInChildApplications="false">
    <system.webServer>
      <!-- WebDAV would otherwise swallow PUT, DELETE, PROPFIND, ... -->
      <modules>
        <remove name="WebDAVModule" />
      </modules>
      <handlers>
        <remove name="WebDAV" />
        <add name="aspNetCore" path="*" verb="*" modules="AspNetCoreModuleV2" resourceType="Unspecified" />
      </handlers>
      <aspNetCore processPath=".\RequestEcho.exe" hostingModel="inprocess"
                  stdoutLogEnabled="false" stdoutLogFile=".\logs\stdout">
        <environmentVariables>
          <!-- the certificate comes from the IIS binding; skip the store search at startup -->
          <environmentVariable name="Echo__ServerCertificate__AutoSelect" value="false" />
        </environmentVariables>
      </aspNetCore>
      <security>
        <requestFiltering allowDoubleEscaping="true" allowHighBitCharacters="true">
          <requestLimits maxAllowedContentLength="104857600" maxUrl="16384" maxQueryString="16384" />
        </requestFiltering>
      </security>
    </system.webServer>
  </location>
</configuration>
```

### Things to keep in mind

- **Console output** (startup messages, `Echo:LogToConsole`) only appears in the stdout log:
  set `stdoutLogEnabled="true"`, create the `logs` folder and give the app pool identity write access.
- **Client certificates**: in the site's *SSL Settings* set *Client certificates* to **Accept**
  (or *Require*). IIS then requests the certificate via TLS renegotiation, which does not work with
  HTTP/2 or TLS 1.3. To request it during the handshake, enable it on the http.sys binding:
  `netsh http update sslcert ipport=0.0.0.0:443 ... clientcertnegotiation=enable`
  (or `hostnameport=<name>:443` for SNI bindings).
- **Windows authentication**: if enabled in IIS, IIS handles the NTLM/Negotiate handshake itself.
  Enable only *Anonymous* if the echo should see and decode the raw `Authorization` headers.
- **Request filtering** blocks some requests before they reach the app, e.g. hidden segments
  (`/bin`, `/App_Data`, `web.config`), denied verbs, double-escaped URLs, bodies over 30 MB (default)
  and long URLs. Relax `<requestFiltering>` as needed (see `web.config` above).
- **http.sys normalizes requests**: absolute-form targets, `OPTIONS *` and malformed requests are
  handled by http.sys (often answered with 400 without reaching the app). The raw request line is
  therefore not always exactly what the client sent. Use the self-hosted exe (Kestrel) for byte-exact analysis.
- **Server certificate selection**: the app pool identity normally cannot read machine private keys,
  so the store search finds nothing. Disable it via `Echo__ServerCertificate__AutoSelect=false` (see above).

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
