using System.Net;
using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace RequestEcho;

/// <summary>
/// Picks the "best" TLS server certificate from a Windows certificate store
/// (default: LocalMachine\My = "Computer certificates / Personal").
/// Used as default certificate for every HTTPS endpoint that has no certificate of its own
/// (<c>Kestrel:Endpoints:*:Certificate</c>) and only if <c>Kestrel:Certificates:Default</c> is not set.
/// </summary>
internal static class ServerCertificatePicker
{
    private const string ServerAuthOid = "1.3.6.1.5.5.7.3.1";
    private const string SubjectAltNameOid = "2.5.29.17";

    private const string DevCertOid = "1.3.6.1.4.1.311.84.1.1";

    /// <summary>
    /// Names of the HTTPS endpoints that have no explicitly configured certificate
    /// (neither their own <c>Certificate</c> nor <c>Kestrel:Certificates:Default</c>).
    /// </summary>
    public static List<string> EndpointsWithoutCertificate(IConfiguration config)
    {
        if (config.GetSection("Kestrel:Certificates:Default").Exists()) return [];

        return config.GetSection("Kestrel:Endpoints").GetChildren()
            .Where(ep => (ep["Url"] ?? "").StartsWith("https:", StringComparison.OrdinalIgnoreCase) &&
                         !ep.GetSection("Certificate").Exists())
            .Select(ep => ep.Key)
            .ToList();
    }

    /// <summary>True if Kestrel would find a usable ASP.NET Core development certificate (CurrentUser\My).</summary>
    public static bool HasDevCertificate()
    {
        try
        {
            using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
            var now = DateTime.Now;
            var found = false;
            foreach (var cert in store.Certificates)
            {
                found |= cert.HasPrivateKey && now >= cert.NotBefore && now <= cert.NotAfter &&
                         cert.Extensions.Cast<X509Extension>().Any(e => e.Oid?.Value == DevCertOid);
                cert.Dispose();
            }
            return found;
        }
        catch (Exception ex) when (ex is CryptographicException or PlatformNotSupportedException)
        {
            return false;
        }
    }

    /// <summary>
    /// Settings (section <c>Echo:ServerCertificate</c>):
    /// <c>AutoSelect</c>, <c>Location</c> (LocalMachine|CurrentUser), <c>Store</c> (My, WebHosting, ...),
    /// <c>Subject</c> (substring filter on subject / DNS names), <c>Thumbprint</c> (exact certificate).
    /// Returns null if nothing suitable was found (Kestrel then uses the ASP.NET Core dev certificate).
    /// </summary>
    public static X509Certificate2? Pick(IConfiguration section)
    {
        var thumbprint = NormalizeThumbprint(section["Thumbprint"]);
        var autoSelect = section.GetValue("AutoSelect", false);
        if (!autoSelect && thumbprint is null) return null;

        var location = section.GetValue("Location", StoreLocation.LocalMachine);
        var storeName = string.IsNullOrWhiteSpace(section["Store"]) ? "My" : section["Store"]!;
        var subjectFilter = string.IsNullOrWhiteSpace(section["Subject"]) ? null : section["Subject"]!.Trim();
        var storeLabel = $@"{location}\{storeName}";

        X509Certificate2Collection all;
        try
        {
            using var store = new X509Store(storeName, location);
            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
            all = store.Certificates;
        }
        catch (Exception ex) when (ex is CryptographicException or PlatformNotSupportedException)
        {
            if (thumbprint is not null)
                throw new InvalidOperationException($"Certificate store {storeLabel} cannot be opened: {ex.Message}", ex);
            Console.WriteLine($"Server certificate: store {storeLabel} cannot be opened ({ex.Message}).");
            return null;
        }

        // Explicit thumbprint: take exactly this certificate (or fail).
        if (thumbprint is not null)
        {
            var cert = all.FirstOrDefault(c => string.Equals(c.Thumbprint, thumbprint, StringComparison.OrdinalIgnoreCase))
                ?? throw new InvalidOperationException($"Certificate with thumbprint {thumbprint} not found in {storeLabel}.");
            if (!CanUsePrivateKey(cert))
                throw new InvalidOperationException(
                    $"Certificate {thumbprint} in {storeLabel} has no usable private key (missing, or no read permission for this account).");
            DisposeAllExcept(all, cert);
            Console.WriteLine($"Server certificate: {storeLabel} by thumbprint -> {Describe(cert)}");
            if (DateTime.Now > cert.NotAfter || DateTime.Now < cert.NotBefore)
                Console.WriteLine("  WARNING: certificate is outside its validity period.");
            return cert;
        }

        // Auto selection.
        var hostNames = GetHostNames();
        var candidates = new List<(X509Certificate2 Cert, bool NameMatch, bool Trusted)>();
        var report = new List<string>();

        foreach (var cert in all)
        {
            var dnsNames = GetDnsNames(cert);
            var reject = Reject(cert, dnsNames, subjectFilter);
            if (reject is not null)
            {
                report.Add($"  - {Describe(cert)}: {reject}");
                continue;
            }

            var nameMatch = dnsNames.Any(n => hostNames.Any(h => NameMatches(n, h)));
            var trusted = IsTrusted(cert);
            candidates.Add((cert, nameMatch, trusted));
            report.Add($"  + {Describe(cert)}: {(nameMatch ? "matches host name" : "no host name match")}, {(trusted ? "trusted chain" : "untrusted chain")}");
        }

        var best = candidates
            .OrderByDescending(c => c.NameMatch)
            .ThenByDescending(c => c.Trusted)
            .ThenByDescending(c => c.Cert.NotAfter)
            .Select(c => c.Cert)
            .FirstOrDefault();

        Console.WriteLine($"Server certificate: auto-select from {storeLabel}" +
                          (subjectFilter is null ? "" : $" (subject filter \"{subjectFilter}\")") +
                          $", host names: {string.Join(", ", hostNames)}");
        foreach (var line in report) Console.WriteLine(line);

        if (best is null)
        {
            Console.WriteLine("  -> no suitable certificate in the store.");
            DisposeAllExcept(all, null);
            return null;
        }

        Console.WriteLine($"  -> selected {best.Thumbprint}");
        DisposeAllExcept(all, best);
        return best;
    }

    private static string? Reject(X509Certificate2 cert, IReadOnlyList<string> dnsNames, string? subjectFilter)
    {
        var now = DateTime.Now;
        if (!cert.HasPrivateKey) return "no private key";
        if (now < cert.NotBefore) return "not yet valid";
        if (now > cert.NotAfter) return "expired";

        var eku = cert.Extensions.OfType<X509EnhancedKeyUsageExtension>().FirstOrDefault();
        if (eku is not null && !eku.EnhancedKeyUsages.Cast<Oid>().Any(o => o.Value == ServerAuthOid))
            return "no Server Authentication EKU";

        var ku = cert.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault();
        if (ku is not null && (ku.KeyUsages & (X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment)) == 0)
            return "key usage does not allow TLS";

        if (subjectFilter is not null &&
            !cert.Subject.Contains(subjectFilter, StringComparison.OrdinalIgnoreCase) &&
            !dnsNames.Any(n => n.Contains(subjectFilter, StringComparison.OrdinalIgnoreCase)))
            return "does not match subject filter";

        if (!CanUsePrivateKey(cert)) return "private key not accessible (run as admin or grant key read permission)";
        return null;
    }

    private static bool CanUsePrivateKey(X509Certificate2 cert)
    {
        try
        {
            using AsymmetricAlgorithm? key = (AsymmetricAlgorithm?)cert.GetRSAPrivateKey()
                                             ?? (AsymmetricAlgorithm?)cert.GetECDsaPrivateKey()
                                             ?? cert.GetDSAPrivateKey();
            return key is not null;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    private static bool IsTrusted(X509Certificate2 cert)
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.ApplicationPolicy.Add(new Oid(ServerAuthOid));
        try
        {
            return chain.Build(cert);
        }
        catch (CryptographicException)
        {
            return false;
        }
        finally
        {
            foreach (var element in chain.ChainElements) element.Certificate.Dispose();
        }
    }

    private static List<string> GetDnsNames(X509Certificate2 cert)
    {
        var names = new List<string>();
        foreach (var ext in cert.Extensions)
        {
            if (ext.Oid?.Value != SubjectAltNameOid) continue;
            try
            {
                var san = ext as X509SubjectAlternativeNameExtension
                          ?? new X509SubjectAlternativeNameExtension(ext.RawData, ext.Critical);
                names.AddRange(san.EnumerateDnsNames());
            }
            catch (CryptographicException)
            {
                // malformed SAN - ignore
            }
        }

        if (names.Count == 0)
        {
            var cn = cert.GetNameInfo(X509NameType.SimpleName, false);
            if (!string.IsNullOrEmpty(cn)) names.Add(cn);
        }
        return names;
    }

    private static List<string> GetHostNames()
    {
        var names = new List<string>();
        void Add(string? n)
        {
            if (!string.IsNullOrWhiteSpace(n) && !names.Contains(n, StringComparer.OrdinalIgnoreCase)) names.Add(n);
        }

        var host = Dns.GetHostName();
        try
        {
            var domain = IPGlobalProperties.GetIPGlobalProperties().DomainName;
            if (!string.IsNullOrEmpty(domain)) Add($"{host}.{domain}");
        }
        catch (NetworkInformationException) { }
        try { Add(Dns.GetHostEntry(host).HostName); } catch (Exception) { }
        Add(host);
        Add(Environment.MachineName);
        return names;
    }

    /// <summary>Exact match or single-label wildcard (<c>*.example.org</c> matches <c>host.example.org</c>).</summary>
    private static bool NameMatches(string certName, string hostName)
    {
        if (string.Equals(certName, hostName, StringComparison.OrdinalIgnoreCase)) return true;
        if (!certName.StartsWith("*.", StringComparison.Ordinal)) return false;
        var dot = hostName.IndexOf('.');
        return dot > 0 && string.Equals(certName[1..], hostName[dot..], StringComparison.OrdinalIgnoreCase);
    }

    private static string? NormalizeThumbprint(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        // Thumbprints copied from the MMC often contain spaces and an invisible U+200E mark.
        return new string(value.Where(Uri.IsHexDigit).ToArray()).ToUpperInvariant();
    }

    private static string Describe(X509Certificate2 cert) =>
        $"{cert.Subject} [{cert.Thumbprint}] valid until {cert.NotAfter:yyyy-MM-dd}";

    private static void DisposeAllExcept(X509Certificate2Collection all, X509Certificate2? keep)
    {
        foreach (var c in all)
            if (!ReferenceEquals(c, keep)) c.Dispose();
    }
}
