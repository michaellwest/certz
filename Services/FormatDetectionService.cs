using certz.Models;

namespace certz.Services;

/// <summary>
/// Detects certificate file formats from extension and content.
/// </summary>
internal static class FormatDetectionService
{
    private static readonly byte[] PemPrefix = "-----BEGIN"u8.ToArray();

    /// <summary>
    /// Detects the format of a certificate file.
    /// </summary>
    internal static async Task<FormatType> DetectFormat(FileInfo file)
    {
        // Check extension first
        var extension = file.Extension.ToLowerInvariant();

        switch (extension)
        {
            case ".pfx":
            case ".p12":
                return FormatType.Pfx;

            case ".der":
                return FormatType.Der;

            case ".pem":
                return FormatType.Pem;

            case ".crt":
            case ".cer":
            case ".key":
                // Ambiguous - check content
                return await DetectFromContent(file);

            default:
                return await DetectFromContent(file);
        }
    }

    /// <summary>
    /// Detects format from file content.
    /// </summary>
    private static async Task<FormatType> DetectFromContent(FileInfo file)
    {
        if (!file.Exists)
        {
            return FormatType.Unknown;
        }

        // Read first bytes to determine format
        var buffer = new byte[16];
        await using var stream = file.OpenRead();
        var bytesRead = await stream.ReadAsync(buffer);

        if (bytesRead == 0)
        {
            return FormatType.Unknown;
        }

        // Check for PEM header
        if (bytesRead >= PemPrefix.Length &&
            buffer.AsSpan(0, PemPrefix.Length).SequenceEqual(PemPrefix))
        {
            return FormatType.Pem;
        }

        // Check for binary ASN.1 (DER or PFX)
        if (bytesRead >= 2 && buffer[0] == 0x30)
        {
            // Both DER and PFX start with ASN.1 SEQUENCE
            // Try to determine if it's a PFX by checking for PKCS#12 structure
            // For simplicity, check file size - PFX is usually larger
            if (file.Length > 500)
            {
                // Could be PFX - try loading as PKCS#12
                return await TryDetectPfx(file) ? FormatType.Pfx : FormatType.Der;
            }
            return FormatType.Der;
        }

        return FormatType.Unknown;
    }

    /// <summary>
    /// Attempts to detect if a file is a PFX by trying to parse it.
    /// </summary>
    private static async Task<bool> TryDetectPfx(FileInfo file)
    {
        try
        {
            // Read entire file
            var data = await File.ReadAllBytesAsync(file.FullName);

            // Try to parse as PKCS#12 with empty password
            // This will fail for password-protected PFX but the exception type helps
            try
            {
                using var cert = System.Security.Cryptography.X509Certificates.X509CertificateLoader
                    .LoadPkcs12(data, null);
                return true;
            }
            catch (System.Security.Cryptography.CryptographicException ex)
            {
                // "The specified network password is not correct" indicates PFX
                return ex.Message.Contains("password", StringComparison.OrdinalIgnoreCase);
            }
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Parses a format string to FormatType enum.
    /// </summary>
    internal static FormatType ParseFormat(string format)
    {
        return format.ToLowerInvariant() switch
        {
            "pem" => FormatType.Pem,
            "der" => FormatType.Der,
            "pfx" or "pkcs12" or "p12" => FormatType.Pfx,
            _ => FormatType.Unknown
        };
    }

    /// <summary>
    /// Gets the default file extension for a format.
    /// </summary>
    internal static string GetDefaultExtension(FormatType format)
    {
        return format switch
        {
            FormatType.Pem => ".pem",
            FormatType.Der => ".der",
            FormatType.Pfx => ".pfx",
            _ => ".bin"
        };
    }

    /// <summary>
    /// Generates output path based on input and target format.
    /// </summary>
    internal static string GenerateOutputPath(FileInfo input, FormatType outputFormat)
    {
        var directory = input.DirectoryName ?? ".";
        var baseName = Path.GetFileNameWithoutExtension(input.Name);
        var extension = GetDefaultExtension(outputFormat);

        return Path.Combine(directory, baseName + extension);
    }

    /// <summary>
    /// Attempts to find a matching key file for a certificate.
    /// </summary>
    internal static FileInfo? FindKeyFile(FileInfo certFile)
    {
        var directory = certFile.DirectoryName ?? ".";
        var baseName = Path.GetFileNameWithoutExtension(certFile.Name);

        // Try common key file naming patterns
        var patterns = new[]
        {
            $"{baseName}.key",
            $"{baseName}-key.pem",
            $"{baseName}.key.pem",
            $"{baseName}_key.pem"
        };

        foreach (var pattern in patterns)
        {
            var keyPath = Path.Combine(directory, pattern);
            if (File.Exists(keyPath))
            {
                return new FileInfo(keyPath);
            }
        }

        return null;
    }
}
