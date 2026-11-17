using Microsoft.Extensions.Primitives;

namespace RequestEcho;

/// <summary>
/// Response control via query parameters (all prefixed with "_" so they rarely clash):
///   _status=503            status code
///   _h.Name=Value          set header (repeat the parameter for multiple values)
///   _h=Name:Value          append header (repeatable)
///   _rm=Name               remove header (e.g. Content-Type, Cache-Control)
///   _delay=1500            delay in ms (max 120000)
///   _body=text             replace the echo with a literal body
///   _pem=1                 include PEM of all client certificates in the dump
/// </summary>
public sealed class ResponseOverrides
{
    public int? Status { get; private set; }
    public int DelayMs { get; private set; }
    public string? Body { get; private set; }
    public bool Pem { get; private set; }

    private readonly List<string> _remove = new();
    private readonly List<(string Name, string[] Values)> _set = new();
    private readonly List<(string Name, string Value)> _append = new();

    /// <summary>Human readable log of what was applied (and what was rejected).</summary>
    public List<string> Log { get; } = new();

    public static bool IsControlKey(string key) =>
        key.StartsWith("_h.", StringComparison.OrdinalIgnoreCase) ||
        key.ToLowerInvariant() is "_status" or "_h" or "_rm" or "_delay" or "_body" or "_pem" or "_help";

    public static ResponseOverrides Parse(IQueryCollection query)
    {
        var o = new ResponseOverrides();
        foreach (var (key, values) in query)
        {
            var value = values.ToString();
            switch (key.ToLowerInvariant())
            {
                case "_status":
                    if (int.TryParse(value, out var s) && s is >= 100 and <= 999) o.Status = s;
                    else o.Log.Add($"REJECTED _status={value} (must be 100..999)");
                    break;

                case "_delay":
                    if (int.TryParse(value, out var ms) && ms >= 0) o.DelayMs = Math.Min(ms, 120_000);
                    else o.Log.Add($"REJECTED _delay={value} (milliseconds expected)");
                    break;

                case "_body":
                    o.Body = string.Join("\n", values.ToArray());
                    break;

                case "_pem":
                    o.Pem = value is not ("0" or "false" or "no");
                    break;

                case "_rm":
                    foreach (var v in values) if (!string.IsNullOrWhiteSpace(v)) o._remove.Add(v!.Trim());
                    break;

                case "_h":
                    foreach (var v in values)
                    {
                        var idx = v?.IndexOf(':') ?? -1;
                        if (idx <= 0) { o.Log.Add($"REJECTED _h={v} (expected Name:Value)"); continue; }
                        o._append.Add((v![..idx].Trim(), v[(idx + 1)..].TrimStart()));
                    }
                    break;

                default:
                    if (key.StartsWith("_h.", StringComparison.OrdinalIgnoreCase) && key.Length > 3)
                        o._set.Add((key[3..], values.Select(v => v ?? "").ToArray()));
                    break;
            }
        }
        return o;
    }

    public void ApplyHeaders(HttpResponse res)
    {
        if (Status is int st) Log.Add($"status   {st}");

        foreach (var name in _remove)
        {
            res.Headers.Remove(name);
            Log.Add($"removed  {name}");
        }

        foreach (var (name, values) in _set)
        {
            if (!Validate(name, values)) continue;
            try
            {
                res.Headers[name] = new StringValues(values);
                Log.Add($"set      {name}: {string.Join(" | ", values)}");
            }
            catch (Exception ex) { Log.Add($"REJECTED {name}: {ex.Message}"); }
        }

        foreach (var (name, value) in _append)
        {
            if (!Validate(name, [value])) continue;
            try
            {
                res.Headers.Append(name, value);
                Log.Add($"appended {name}: {value}");
            }
            catch (Exception ex) { Log.Add($"REJECTED {name}: {ex.Message}"); }
        }

        if (DelayMs > 0) Log.Add($"delay    {DelayMs} ms");
        if (Body != null) Log.Add($"body     replaced by _body ({Body.Length} chars)");
    }

    private bool Validate(string name, IEnumerable<string> values)
    {
        if (name.Length == 0 || !name.All(IsTokenChar))
        {
            Log.Add($"REJECTED header name '{name}' (not an RFC 9110 token)");
            return false;
        }
        foreach (var v in values)
        {
            if (v.Any(c => (c < 0x20 && c != '\t') || c > 0x7E))
            {
                Log.Add($"REJECTED {name}: value contains control or non-ASCII characters");
                return false;
            }
        }
        return true;
    }

    private static bool IsTokenChar(char c) =>
        char.IsAsciiLetterOrDigit(c) || "!#$%&'*+-.^_`|~".Contains(c);
}
