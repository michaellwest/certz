using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace certz.Services;

/// <summary>
/// Handles streaming certificate output to stdout for pipe mode.
/// </summary>
internal static class PipeOutputService
{
    /// <summary>
    /// Writes certificate in specified format to stdout.
    /// </summary>
    /// <param name="certificate">The certificate to output.</param>
    /// <param name="format">Output format: pem, pfx, cert, or key.</param>
    /// <param name="password">Password for PFX output (optional, will be generated if not provided).</param>
    /// <returns>The password used for PFX format (if applicable).</returns>
    internal static async Task<string?> WritePipeOutput(
        X509Certificate2 certificate,
        string format,
        string? password)
    {
        return format.ToLowerInvariant() switch
        {
            "pem" => await WritePemOutput(certificate),
            "pfx" => await WritePfxOutput(certificate, password),
            "cert" => await WriteCertOnlyOutput(certificate),
            "key" => await WriteKeyOnlyOutput(certificate),
            _ => throw new ArgumentException($"Unknown pipe format: {format}")
        };
    }

    private static async Task<string?> WritePemOutput(X509Certificate2 certificate)
    {
        var sb = new StringBuilder();

        // Certificate PEM
        sb.AppendLine("-----BEGIN CERTIFICATE-----");
        sb.AppendLine(Convert.ToBase64String(certificate.RawData, Base64FormattingOptions.InsertLineBreaks));
        sb.AppendLine("-----END CERTIFICATE-----");

        // Private key PEM
        if (certificate.HasPrivateKey)
        {
            var keyPem = ExportPrivateKeyPem(certificate);
            sb.Append(keyPem);
        }

        await Console.Out.WriteAsync(sb.ToString());
        return null;
    }

    private static async Task<string?> WritePfxOutput(X509Certificate2 certificate, string? password)
    {
        var actualPassword = password;

        if (string.IsNullOrEmpty(actualPassword))
        {
            // Generate random password and output to stderr
            actualPassword = CertificateUtilities.GenerateSecurePassword();
            await Console.Error.WriteLineAsync($"PASSWORD: {actualPassword}");
        }

        var pfxBytes = certificate.Export(X509ContentType.Pfx, actualPassword);
        var base64 = Convert.ToBase64String(pfxBytes);
        await Console.Out.WriteAsync(base64);

        return actualPassword;
    }

    private static async Task<string?> WriteCertOnlyOutput(X509Certificate2 certificate)
    {
        var sb = new StringBuilder();
        sb.AppendLine("-----BEGIN CERTIFICATE-----");
        sb.AppendLine(Convert.ToBase64String(certificate.RawData, Base64FormattingOptions.InsertLineBreaks));
        sb.AppendLine("-----END CERTIFICATE-----");

        await Console.Out.WriteAsync(sb.ToString());
        return null;
    }

    private static async Task<string?> WriteKeyOnlyOutput(X509Certificate2 certificate)
    {
        if (!certificate.HasPrivateKey)
        {
            throw new InvalidOperationException("Certificate does not have a private key.");
        }

        var keyPem = ExportPrivateKeyPem(certificate);
        await Console.Out.WriteAsync(keyPem);
        return null;
    }

    private static string ExportPrivateKeyPem(X509Certificate2 certificate)
    {
        var sb = new StringBuilder();

        using var ecdsa = certificate.GetECDsaPrivateKey();
        if (ecdsa != null)
        {
            var keyBytes = ecdsa.ExportPkcs8PrivateKey();
            sb.AppendLine("-----BEGIN PRIVATE KEY-----");
            sb.AppendLine(Convert.ToBase64String(keyBytes, Base64FormattingOptions.InsertLineBreaks));
            sb.AppendLine("-----END PRIVATE KEY-----");
            return sb.ToString();
        }

        using var rsa = certificate.GetRSAPrivateKey();
        if (rsa != null)
        {
            var keyBytes = rsa.ExportPkcs8PrivateKey();
            sb.AppendLine("-----BEGIN PRIVATE KEY-----");
            sb.AppendLine(Convert.ToBase64String(keyBytes, Base64FormattingOptions.InsertLineBreaks));
            sb.AppendLine("-----END PRIVATE KEY-----");
            return sb.ToString();
        }

        throw new InvalidOperationException("Unsupported key type for export.");
    }
}
