using System.IO.Pipelines;
using System.Text;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Server.Kestrel.Core;

namespace RequestEcho;

/// <summary>
/// Writes the bytes of every connection 1:1 to the console – after TLS decryption,
/// i.e. exactly what Kestrel's HTTP parser receives and what it sends back.
/// HTTP/2 is binary (frames + HPACK); for such connections the request/response is
/// logged per request in reconstructed form instead (see <see cref="LogReconstructed"/>).
/// </summary>
public static class WireLog
{
    private static readonly object Gate = new();
    private static readonly byte[] Http2Preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"u8.ToArray();

    public static bool Enabled { get; set; } = true;
    public static int MaxBytesPerChunk { get; set; } = 64 * 1024;

    /// <summary>Connection middleware. Must be added AFTER UseHttps so it sees plaintext.</summary>
    public static void UseWireLog(this ListenOptions listenOptions, bool https) =>
        listenOptions.Use(next => async ctx =>
        {
            if (!Enabled) { await next(ctx); return; }

            var state = new ConnectionState(ctx.ConnectionId);
            var original = ctx.Transport;
            var stream = new LoggingStream(original.Input.AsStream(leaveOpen: true), original.Output.AsStream(leaveOpen: true), state);
            var reader = PipeReader.Create(stream, new StreamPipeReaderOptions(leaveOpen: true));
            var writer = PipeWriter.Create(stream, new StreamPipeWriterOptions(leaveOpen: true));
            ctx.Transport = new DuplexPipe(reader, writer);

            Info(state.Id, $"connection opened  {ctx.RemoteEndPoint} -> {ctx.LocalEndPoint}{(https ? "  (TLS - shown decrypted)" : "")}");
            try
            {
                await next(ctx);
            }
            finally
            {
                await reader.CompleteAsync();
                await writer.CompleteAsync();
                ctx.Transport = original;
                Info(state.Id, $"connection closed  ({state.BytesIn} bytes in, {state.BytesOut} bytes out)");
            }
        });

    /// <summary>For HTTP/2+ requests: log request and response as text (pseudo-headers + headers + body).</summary>
    public static void LogReconstructed(HttpContext ctx, byte[] requestBody, long requestBodyTotal, string? responseBody)
    {
        if (!Enabled) return;
        var req = ctx.Request;
        var rawTarget = ctx.Features.Get<IHttpRequestFeature>()?.RawTarget;
        if (string.IsNullOrEmpty(rawTarget)) rawTarget = req.PathBase + req.Path + req.QueryString;

        var sb = new StringBuilder();
        sb.Append($":method: {req.Method}\n:scheme: {req.Scheme}\n:authority: {req.Host}\n:path: {rawTarget}\n");
        foreach (var h in req.Headers)
            foreach (var v in h.Value)
                sb.Append($"{h.Key}: {v}\n");
        sb.Append('\n');
        if (requestBodyTotal > 0) sb.Append(Render(requestBody));
        if (requestBodyTotal > requestBody.Length) sb.Append($"\n[... {requestBodyTotal - requestBody.Length} more bytes not captured]");
        Block(ctx.Connection.Id, inbound: true, $"{req.Protocol} request (reconstructed from decoded frames)", sb.ToString());

        var res = ctx.Response;
        sb.Clear();
        sb.Append($":status: {res.StatusCode}\n");
        foreach (var h in res.Headers)
            foreach (var v in h.Value)
                sb.Append($"{h.Key}: {v}\n");
        sb.Append('\n');
        if (responseBody != null) sb.Append(Render(Encoding.UTF8.GetBytes(responseBody)));
        Block(ctx.Connection.Id, inbound: false, $"{req.Protocol} response (reconstructed)", sb.ToString());
    }

    // ------------------------------------------------------------------ output

    private static void Info(string conn, string text)
    {
        lock (Gate)
        {
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.Out.WriteLine($"=== {DateTime.Now:HH:mm:ss.fff} [{conn}] {text}");
            Console.ResetColor();
        }
    }

    private static void Block(string conn, bool inbound, string title, string content)
    {
        lock (Gate)
        {
            Console.ForegroundColor = inbound ? ConsoleColor.Cyan : ConsoleColor.Yellow;
            Console.Out.WriteLine($">>> {DateTime.Now:HH:mm:ss.fff} [{conn}] {(inbound ? "client -> server" : "server -> client")}  {title}");
            Console.ResetColor();
            Console.Out.Write(content);
            if (!content.EndsWith('\n')) Console.Out.WriteLine();
            Console.ForegroundColor = inbound ? ConsoleColor.Cyan : ConsoleColor.Yellow;
            Console.Out.WriteLine("<<<");
            Console.ResetColor();
        }
    }

    private static void Chunk(ConnectionState st, bool inbound, ReadOnlySpan<byte> data)
    {
        if (data.Length == 0) return;
        if (inbound) st.BytesIn += data.Length; else st.BytesOut += data.Length;

        if (inbound && !st.SawFirstInbound)
        {
            st.SawFirstInbound = true;
            if (data.StartsWith(Http2Preface))
            {
                st.IsHttp2 = true;
                Info(st.Id, "HTTP/2 connection (binary frames) - requests/responses are logged reconstructed per request");
            }
        }
        if (st.IsHttp2) return;

        var shown = data.Length > MaxBytesPerChunk ? data[..MaxBytesPerChunk] : data;
        var text = Render(shown);
        if (data.Length > MaxBytesPerChunk) text += $"\n[... {data.Length - MaxBytesPerChunk} more bytes in this chunk not shown]";
        Block(st.Id, inbound, $"{data.Length} bytes", text);
    }

    /// <summary>
    /// Text 1:1 (UTF-8 if valid, otherwise ISO-8859-1). CR LF is shown as a line break, other
    /// control characters as \xNN. Mostly-binary data is shown as a hex dump.
    /// </summary>
    private static string Render(ReadOnlySpan<byte> data)
    {
        int control = 0;
        foreach (var b in data) if (b < 0x20 && b is not (0x0D or 0x0A or 0x09)) control++;
        if (data.Length > 16 && control * 10 > data.Length) return HexDump(data);

        string s;
        try { s = new UTF8Encoding(false, true).GetString(data); }
        catch { s = Encoding.Latin1.GetString(data); }

        var sb = new StringBuilder(s.Length);
        for (int i = 0; i < s.Length; i++)
        {
            var c = s[i];
            if (c == '\r' && i + 1 < s.Length && s[i + 1] == '\n') continue; // CRLF -> newline
            if (c is '\n' or '\t' || !char.IsControl(c)) sb.Append(c);
            else sb.Append($"\\x{(int)c:x2}");
        }
        return sb.ToString();
    }

    private static string HexDump(ReadOnlySpan<byte> data)
    {
        var sb = new StringBuilder();
        for (int off = 0; off < data.Length; off += 16)
        {
            var line = data.Slice(off, Math.Min(16, data.Length - off));
            sb.Append($"  {off:x8}  ");
            for (int i = 0; i < 16; i++)
            {
                sb.Append(i < line.Length ? line[i].ToString("x2") + " " : "   ");
                if (i == 7) sb.Append(' ');
            }
            sb.Append(" |");
            foreach (var b in line) sb.Append(b is >= 0x20 and < 0x7F ? (char)b : '.');
            sb.Append("|\n");
        }
        return sb.ToString();
    }

    // ------------------------------------------------------------------ plumbing

    private sealed class ConnectionState(string id)
    {
        public string Id { get; } = id;
        public bool SawFirstInbound { get; set; }
        public bool IsHttp2 { get; set; }
        public long BytesIn { get; set; }
        public long BytesOut { get; set; }
    }

    private sealed class DuplexPipe(PipeReader input, PipeWriter output) : IDuplexPipe
    {
        public PipeReader Input { get; } = input;
        public PipeWriter Output { get; } = output;
    }

    private sealed class LoggingStream(Stream input, Stream output, ConnectionState state) : Stream
    {
        public override bool CanRead => true;
        public override bool CanWrite => true;
        public override bool CanSeek => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Flush() => output.Flush();
        public override Task FlushAsync(CancellationToken ct) => output.FlushAsync(ct);

        public override int Read(byte[] buffer, int offset, int count)
        {
            var n = input.Read(buffer, offset, count);
            Chunk(state, true, buffer.AsSpan(offset, n));
            return n;
        }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default)
        {
            var n = await input.ReadAsync(buffer, ct);
            Chunk(state, true, buffer.Span[..n]);
            return n;
        }

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken ct) =>
            ReadAsync(buffer.AsMemory(offset, count), ct).AsTask();

        public override void Write(byte[] buffer, int offset, int count)
        {
            Chunk(state, false, buffer.AsSpan(offset, count));
            output.Write(buffer, offset, count);
        }

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default)
        {
            Chunk(state, false, buffer.Span);
            return output.WriteAsync(buffer, ct);
        }

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken ct) =>
            WriteAsync(buffer.AsMemory(offset, count), ct).AsTask();
    }
}
