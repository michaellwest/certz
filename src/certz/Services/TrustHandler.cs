using System.Diagnostics;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using certz.Models;

namespace certz.Services;

/// <summary>
/// Service for managing certificates in trust stores.
/// </summary>
internal static class TrustHandler
{
    /// <summary>
    /// Adds a certificate to the specified trust store.
    /// </summary>
    public static TrustOperationResult AddToStore(string filePath, string? password, string storeName, string storeLocation)
    {
        var location = StoreListHandler.ParseStoreLocation(storeLocation);
        var name = StoreListHandler.ParseStoreName(storeName);

        if (OperatingSystem.IsMacOS())
        {
            throw new PlatformNotSupportedException(
                "System-wide trust store management on macOS is not yet supported. " +
                "Use 'sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain <file>' manually.");
        }

        // Check admin requirement for LocalMachine
        if (location == StoreLocation.LocalMachine && !IsRunningAsAdmin())
        {
            throw new InvalidOperationException(
                "Administrator privileges required to modify LocalMachine certificate store. " +
                "Run the command as Administrator (Windows) or as root (Linux), " +
                "or use '--location CurrentUser' for user-level trust.");
        }

        var cert = LoadCertificateFromFile(filePath, password);

        try
        {
            // On Linux, LocalMachine trust requires distro-specific shell commands
            if (OperatingSystem.IsLinux() && location == StoreLocation.LocalMachine)
            {
                return AddToLinuxSystemStore(cert);
            }

            using var store = new X509Store(name, location);
            store.Open(OpenFlags.ReadWrite);
            store.Add(cert);

            return new TrustOperationResult
            {
                Success = true,
                Operation = TrustOperationType.Add,
                StoreName = name.ToString(),
                StoreLocation = location.ToString(),
                Certificates =
                [
                    new TrustCertificateInfo
                    {
                        Subject = cert.Subject,
                        Thumbprint = cert.Thumbprint,
                        NotAfter = cert.NotAfter
                    }
                ]
            };
        }
        finally
        {
            cert.Dispose();
        }
    }

    /// <summary>
    /// Finds certificates matching the specified criteria.
    /// </summary>
    public static List<X509Certificate2> FindMatchingCertificates(string? thumbprint, string? subject, string storeName, string storeLocation)
    {
        var location = StoreListHandler.ParseStoreLocation(storeLocation);
        var name = StoreListHandler.ParseStoreName(storeName);

        using var store = new X509Store(name, location);
        store.Open(OpenFlags.ReadOnly);

        var matching = new List<X509Certificate2>();

        if (!string.IsNullOrEmpty(thumbprint))
        {
            var normalizedThumbprint = thumbprint.Replace(" ", "").ToUpperInvariant();

            if (normalizedThumbprint.Length == 40)
            {
                // Exact match for full thumbprint (40 hex characters = SHA-1)
                var found = store.Certificates.Find(X509FindType.FindByThumbprint, normalizedThumbprint, false);
                foreach (var cert in found)
                {
                    // Clone the cert to avoid disposal issues when store closes
                    matching.Add(X509CertificateLoader.LoadCertificate(cert.RawData));
                }
            }
            else
            {
                // Prefix match for partial thumbprint (8+ characters)
                foreach (var cert in store.Certificates)
                {
                    if (cert.Thumbprint.StartsWith(normalizedThumbprint, StringComparison.OrdinalIgnoreCase))
                    {
                        // Clone the cert to avoid disposal issues when store closes
                        matching.Add(X509CertificateLoader.LoadCertificate(cert.RawData));
                    }
                }
            }
        }
        else if (!string.IsNullOrEmpty(subject))
        {
            // Find by subject pattern (supports wildcards)
            var pattern = WildcardToRegex(subject);
            var regex = new Regex(pattern, RegexOptions.IgnoreCase);

            foreach (var cert in store.Certificates)
            {
                if (regex.IsMatch(cert.Subject))
                {
                    // Clone the cert to avoid disposal issues when store closes
                    matching.Add(X509CertificateLoader.LoadCertificate(cert.RawData));
                }
            }
        }

        return matching;
    }

    /// <summary>
    /// Removes certificates from the store.
    /// </summary>
    public static TrustOperationResult RemoveFromStore(List<X509Certificate2> certificates, string storeName, string storeLocation)
    {
        var location = StoreListHandler.ParseStoreLocation(storeLocation);
        var name = StoreListHandler.ParseStoreName(storeName);

        if (OperatingSystem.IsMacOS())
        {
            throw new PlatformNotSupportedException(
                "System-wide trust store management on macOS is not yet supported. " +
                "Use 'sudo security remove-trusted-cert <file>' manually.");
        }

        // Check admin requirement for LocalMachine
        if (location == StoreLocation.LocalMachine && !IsRunningAsAdmin())
        {
            throw new InvalidOperationException(
                "Administrator privileges required to modify LocalMachine certificate store. " +
                "Run the command as Administrator (Windows) or as root (Linux), " +
                "or use '--location CurrentUser' for user-level trust.");
        }

        // On Linux, LocalMachine trust requires distro-specific shell commands
        if (OperatingSystem.IsLinux() && location == StoreLocation.LocalMachine)
        {
            return RemoveFromLinuxSystemStore(certificates);
        }

        using var store = new X509Store(name, location);
        store.Open(OpenFlags.ReadWrite);

        var removedCerts = new List<TrustCertificateInfo>();

        foreach (var cert in certificates)
        {
            try
            {
                // Find the actual certificate in the store by thumbprint
                var found = store.Certificates.Find(X509FindType.FindByThumbprint, cert.Thumbprint, false);
                if (found.Count > 0)
                {
                    store.Remove(found[0]);
                    removedCerts.Add(new TrustCertificateInfo
                    {
                        Subject = cert.Subject,
                        Thumbprint = cert.Thumbprint,
                        NotAfter = cert.NotAfter
                    });
                }
            }
            finally
            {
                cert.Dispose();
            }
        }

        return new TrustOperationResult
        {
            Success = true,
            Operation = TrustOperationType.Remove,
            StoreName = name.ToString(),
            StoreLocation = location.ToString(),
            Certificates = removedCerts
        };
    }

    /// <summary>
    /// Checks if the current process is running with administrator privileges.
    /// On Windows this checks for the Administrator role; on Linux/macOS it checks for root (uid 0).
    /// </summary>
    internal static bool IsRunningAsAdmin()
    {
        if (OperatingSystem.IsWindows())
        {
            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        // Environment.IsPrivilegedProcess returns true when uid==0 (root) on Linux/macOS
        return Environment.IsPrivilegedProcess;
    }

    /// <summary>
    /// Detects the Linux distro CA anchor directory and the command to refresh the system trust store.
    /// Returns (anchorDir, updateCommand) or throws if unsupported.
    /// </summary>
    private static (string AnchorDir, string UpdateCommand) DetectLinuxCaStore()
    {
        if (Directory.Exists("/usr/local/share/ca-certificates"))
            return ("/usr/local/share/ca-certificates", "update-ca-certificates");

        if (Directory.Exists("/etc/pki/ca-trust/source/anchors"))
            return ("/etc/pki/ca-trust/source/anchors", "update-ca-trust");

        if (Directory.Exists("/etc/ca-certificates/trust-source/anchors"))
            return ("/etc/ca-certificates/trust-source/anchors", "trust extract-compat");

        throw new PlatformNotSupportedException(
            "Unable to detect Linux CA anchor directory. " +
            "Supported distros: Debian/Ubuntu (update-ca-certificates), " +
            "RHEL/Fedora (update-ca-trust), Arch (trust extract-compat).");
    }

    /// <summary>
    /// Runs a shell command and waits for it to exit, throwing if it fails.
    /// </summary>
    private static void RunShellCommand(string command, string arguments)
    {
        using var proc = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = command,
                Arguments = arguments,
                UseShellExecute = false,
                RedirectStandardOutput = false,
                RedirectStandardError = false
            }
        };
        proc.Start();
        proc.WaitForExit();
        if (proc.ExitCode != 0)
        {
            throw new InvalidOperationException(
                $"Command '{command} {arguments}' exited with code {proc.ExitCode}.");
        }
    }

    /// <summary>
    /// Adds a certificate to the Linux system CA store by copying it to the distro anchor
    /// directory and running the distro's CA refresh command.
    /// </summary>
    internal static TrustOperationResult AddToLinuxSystemStore(X509Certificate2 cert)
    {
        var (anchorDir, updateCommand) = DetectLinuxCaStore();
        var certFileName = $"certz-{cert.Thumbprint}.crt";
        var destPath = Path.Combine(anchorDir, certFileName);

        // Export certificate as PEM
        var pem = cert.ExportCertificatePem();
        File.WriteAllText(destPath, pem);

        // Refresh system trust store
        var parts = updateCommand.Split(' ', 2);
        var cmd = parts[0];
        var args = parts.Length > 1 ? parts[1] : string.Empty;
        RunShellCommand(cmd, args);

        return new TrustOperationResult
        {
            Success = true,
            Operation = TrustOperationType.Add,
            StoreName = "LocalMachine",
            StoreLocation = "LocalMachine",
            Certificates =
            [
                new TrustCertificateInfo
                {
                    Subject = cert.Subject,
                    Thumbprint = cert.Thumbprint,
                    NotAfter = cert.NotAfter
                }
            ]
        };
    }

    /// <summary>
    /// Removes certificates from the Linux system CA store by deleting the anchor files
    /// and running the distro's CA refresh command.
    /// </summary>
    private static TrustOperationResult RemoveFromLinuxSystemStore(List<X509Certificate2> certificates)
    {
        var (anchorDir, updateCommand) = DetectLinuxCaStore();
        var removedCerts = new List<TrustCertificateInfo>();

        foreach (var cert in certificates)
        {
            try
            {
                var certFileName = $"certz-{cert.Thumbprint}.crt";
                var destPath = Path.Combine(anchorDir, certFileName);

                if (File.Exists(destPath))
                {
                    File.Delete(destPath);
                    removedCerts.Add(new TrustCertificateInfo
                    {
                        Subject = cert.Subject,
                        Thumbprint = cert.Thumbprint,
                        NotAfter = cert.NotAfter
                    });
                }
            }
            finally
            {
                cert.Dispose();
            }
        }

        if (removedCerts.Count > 0)
        {
            var parts = updateCommand.Split(' ', 2);
            var cmd = parts[0];
            var args = parts.Length > 1 ? parts[1] : string.Empty;
            RunShellCommand(cmd, args);
        }

        return new TrustOperationResult
        {
            Success = true,
            Operation = TrustOperationType.Remove,
            StoreName = "LocalMachine",
            StoreLocation = "LocalMachine",
            Certificates = removedCerts
        };
    }

    /// <summary>
    /// Loads a certificate from a file.
    /// </summary>
    private static X509Certificate2 LoadCertificateFromFile(string path, string? password)
    {
        var extension = Path.GetExtension(path).ToLowerInvariant();

        return extension switch
        {
            ".pfx" or ".p12" => LoadPfx(path, password),
            ".pem" => LoadPem(path),
            ".crt" or ".cer" => LoadCertFile(path),
            ".der" => LoadDer(path),
            _ => AutoDetectAndLoad(path, password)
        };
    }

    private static X509Certificate2 LoadPfx(string path, string? password)
    {
        var pfxData = File.ReadAllBytes(path);
        return X509CertificateLoader.LoadPkcs12(pfxData, password, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
    }

    private static X509Certificate2 LoadPem(string path)
    {
        var pemContent = File.ReadAllText(path);

        // Find the first certificate block
        var certMatch = Regex.Match(pemContent, @"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", RegexOptions.Singleline);

        if (!certMatch.Success)
        {
            throw new InvalidOperationException("No certificate found in PEM file.");
        }

        // Check if there's a private key
        if (pemContent.Contains("-----BEGIN PRIVATE KEY-----") ||
            pemContent.Contains("-----BEGIN RSA PRIVATE KEY-----") ||
            pemContent.Contains("-----BEGIN EC PRIVATE KEY-----"))
        {
            return X509Certificate2.CreateFromPem(certMatch.Value, pemContent);
        }

        return X509Certificate2.CreateFromPem(certMatch.Value);
    }

    private static X509Certificate2 LoadCertFile(string path)
    {
        var data = File.ReadAllBytes(path);

        // Try PEM first
        var text = Encoding.UTF8.GetString(data);
        if (text.Contains("-----BEGIN CERTIFICATE-----"))
        {
            return LoadPem(path);
        }

        // Otherwise treat as DER
        return X509CertificateLoader.LoadCertificate(data);
    }

    private static X509Certificate2 LoadDer(string path)
    {
        var data = File.ReadAllBytes(path);
        return X509CertificateLoader.LoadCertificate(data);
    }

    private static X509Certificate2 AutoDetectAndLoad(string path, string? password)
    {
        var data = File.ReadAllBytes(path);

        // Try to detect file type
        var text = Encoding.UTF8.GetString(data);

        // Check for PEM
        if (text.Contains("-----BEGIN"))
        {
            return LoadPem(path);
        }

        // Try PFX
        try
        {
            return LoadPfx(path, password);
        }
        catch
        {
            // Not a PFX
        }

        // Try DER
        try
        {
            return X509CertificateLoader.LoadCertificate(data);
        }
        catch
        {
            throw new InvalidOperationException($"Unable to determine certificate format for: {path}");
        }
    }

    /// <summary>
    /// Converts a wildcard pattern to a regex pattern.
    /// </summary>
    private static string WildcardToRegex(string pattern)
    {
        return "^" + Regex.Escape(pattern)
            .Replace("\\*", ".*")
            .Replace("\\?", ".") + "$";
    }
}
