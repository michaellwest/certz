using System.Net.Security;
using System.Net.Sockets;
using certz.Models;

namespace certz.Services;

/// <summary>
/// Service for exporting certificates from remote URLs and certificate stores.
/// </summary>
internal static class ExportService
{
    /// <summary>
    /// Exports a certificate from a remote URL.
    /// </summary>
    /// <param name="options">The export options.</param>
    /// <returns>The export result.</returns>
    internal static async Task<ExportResult> ExportFromUrl(ExportFromUrlOptions options)
    {
        // Connect to remote host and retrieve certificate
        RemoteCertificateValidationCallback certCallback = (_, _, _, _) => true;
        using var client = new TcpClient(options.Url.Host, 443);
        using var sslStream = new SslStream(client.GetStream(), true, certCallback);
        await sslStream.AuthenticateAsClientAsync(options.Url.Host);
        var serverCertificate = sslStream.RemoteCertificate
            ?? throw new CertificateException($"Could not retrieve certificate from {options.Url}");
        var certificate = new X509Certificate2(serverCertificate);

        // Handle password for PFX
        bool passwordWasGenerated = false;
        string? password = options.Password;
        if (options.PfxFile != null && string.IsNullOrEmpty(password))
        {
            password = CertificateUtilities.GenerateSecurePassword();
            passwordWasGenerated = true;
        }

        var outputFiles = new List<string>();

        // Save certificate files
        if (options.PfxFile != null)
        {
            await CertificateUtilities.WriteCertificateToFile(
                certificate,
                options.PfxFile.FullName,
                password!,
                CertificateFileType.Pfx,
                displayPassword: false,
                passwordFile: options.PasswordFile,
                quiet: true);
            outputFiles.Add(options.PfxFile.FullName);
        }

        if (options.CertFile != null)
        {
            await CertificateUtilities.WriteCertificateToFile(
                certificate,
                options.CertFile.FullName,
                password ?? string.Empty,
                CertificateFileType.PemCer,
                quiet: true);
            outputFiles.Add(options.CertFile.FullName);
        }

        if (options.KeyFile != null)
        {
            await CertificateUtilities.WriteCertificateToFile(
                certificate,
                options.KeyFile.FullName,
                password ?? string.Empty,
                CertificateFileType.PemKey,
                quiet: true);
            outputFiles.Add(options.KeyFile.FullName);
        }

        // Write password to file if generated and file specified
        if (passwordWasGenerated && options.PasswordFile != null)
        {
            options.PasswordFile.Directory?.Create();
            await File.WriteAllTextAsync(options.PasswordFile.FullName, password);
        }

        return new ExportResult
        {
            Success = true,
            Subject = certificate.SubjectName.Format(false),
            Issuer = certificate.IssuerName.Format(false),
            Thumbprint = certificate.Thumbprint,
            NotAfter = certificate.NotAfter,
            Source = $"URL: {options.Url}",
            OutputFiles = outputFiles.ToArray(),
            GeneratedPassword = passwordWasGenerated ? password : null,
            PasswordWasGenerated = passwordWasGenerated
        };
    }

    /// <summary>
    /// Exports a certificate from a certificate store.
    /// </summary>
    /// <param name="options">The export options.</param>
    /// <returns>The export result.</returns>
    /// <exception cref="CertificateException">Thrown when the certificate is not found.</exception>
    internal static async Task<ExportResult> ExportFromStore(ExportFromStoreOptions options)
    {
        // Handle password for PFX
        bool passwordWasGenerated = false;
        string? password = options.Password;
        if (options.PfxFile != null && string.IsNullOrEmpty(password))
        {
            password = CertificateUtilities.GenerateSecurePassword();
            passwordWasGenerated = true;
        }

        // Open store and find certificate
        using var store = new X509Store(options.StoreName, options.StoreLocation, OpenFlags.ReadOnly);
        var certificate = store.Certificates
            .FirstOrDefault(c => c.Thumbprint.Equals(options.Thumbprint, StringComparison.InvariantCultureIgnoreCase));

        if (certificate == null)
        {
            throw new CertificateException($"Certificate with thumbprint {options.Thumbprint} not found in {options.StoreLocation}\\{options.StoreName}");
        }

        var outputFiles = new List<string>();

        // Save certificate files
        if (options.PfxFile != null)
        {
            await CertificateUtilities.WriteCertificateToFile(
                certificate,
                options.PfxFile.FullName,
                password!,
                CertificateFileType.Pfx,
                displayPassword: false,
                passwordFile: options.PasswordFile,
                quiet: true);
            outputFiles.Add(options.PfxFile.FullName);
        }

        if (options.CertFile != null)
        {
            await CertificateUtilities.WriteCertificateToFile(
                certificate,
                options.CertFile.FullName,
                password ?? string.Empty,
                CertificateFileType.PemCer,
                quiet: true);
            outputFiles.Add(options.CertFile.FullName);
        }

        if (options.KeyFile != null)
        {
            await CertificateUtilities.WriteCertificateToFile(
                certificate,
                options.KeyFile.FullName,
                password ?? string.Empty,
                CertificateFileType.PemKey,
                quiet: true);
            outputFiles.Add(options.KeyFile.FullName);
        }

        // Write password to file if generated and file specified
        if (passwordWasGenerated && options.PasswordFile != null)
        {
            options.PasswordFile.Directory?.Create();
            await File.WriteAllTextAsync(options.PasswordFile.FullName, password);
        }

        store.Close();

        return new ExportResult
        {
            Success = true,
            Subject = certificate.SubjectName.Format(false),
            Issuer = certificate.IssuerName.Format(false),
            Thumbprint = certificate.Thumbprint,
            NotAfter = certificate.NotAfter,
            Source = $"Store: {options.StoreLocation}\\{options.StoreName}",
            OutputFiles = outputFiles.ToArray(),
            GeneratedPassword = passwordWasGenerated ? password : null,
            PasswordWasGenerated = passwordWasGenerated
        };
    }
}
