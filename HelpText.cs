namespace RequestEcho;

public static class HelpText
{
    public const string Text = """
        RequestEcho - diagnostic echo endpoint
        ======================================

        Every path and every HTTP method is answered with a plain-text dump of the request:
          - raw request line, all headers, body
          - client IP/port (direct TCP peer) and local socket, IP classification
          - TLS details of this hop (protocol, cipher, SNI) and the client certificate
          - proxy chain analysis (X-Forwarded-*, Forwarded, Via, CDN/LB specific headers)
          - decoded content: Basic auth, JWT (header/claims/exp/cnf), NTLM/Kerberos,
            Digest, AWS SigV4, cookies, traceparent, Base64-JSON headers,
            client certificates forwarded as headers (PEM, URL-encoded PEM, Base64 DER,
            RFC 9440 Client-Cert, Envoy XFCC, IIS ARR X-ARR-ClientCert, AWS ALB ...)

        Response control via query parameters
        -------------------------------------
          _status=<code>         response status, e.g. _status=503
          _h.<Name>=<Value>      SET a response header; repeat for multiple values
                                   ?_h.X-Test=1&_h.Set-Cookie=a%3D1&_h.Set-Cookie=b%3D2
          _h=<Name>:<Value>      APPEND a response header (repeatable)
                                   ?_h=Strict-Transport-Security:max-age%3D60
          _rm=<Name>             remove a header the app sets by default (Content-Type, Cache-Control)
          _delay=<ms>            wait before answering (max 120000) - for proxy timeout tests
          _body=<text>           send this literal text instead of the dump
          _pem=1                 include PEM of every client certificate in the dump
          _help                  this text

          Examples:
            /?_status=302&_h.Location=https%3A%2F%2Fexample.org%2F
            /?_status=401&_h.WWW-Authenticate=Basic%20realm%3D%22test%22
            /?_h.Content-Type=application/json&_body=%7B%22ok%22%3Atrue%7D
            /?_delay=65000                       (does the proxy cut off at 60 s?)

          Notes:
            - Remember to URL-encode values ('=' -> %3D, ';' -> %3B, '&' -> %26, ' ' -> %20).
            - Header values must be printable ASCII; invalid ones are rejected and reported.
            - For 1xx/204/304 and HEAD no body is sent - the dump is written to the console log.
            - Setting a wrong Content-Length makes Kestrel abort the response (on purpose testable).
            - The control parameters still appear in the echoed request.
        """;
}
