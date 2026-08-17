namespace certz.Services;

/// <summary>
/// Writes a set of certificates to individual files in a directory.
/// </summary>
/// <remarks>
/// Takes certificates rather than chain elements so any producer can use it - the
/// inspected chain today, and certificates built by other commands later.
/// </remarks>
internal static class ChainExportService
{
    /// <summary>
    /// Filename schemes accepted by --naming.
    /// </summary>
    internal static readonly string[] NamingSchemes =
        ["index-cn-thumbprint", "cn-thumbprint", "thumbprint", "cn"];

    /// <summary>
    /// Windows device names, which resolve regardless of directory or extension.
    /// </summary>
    private static readonly HashSet<string> ReservedDeviceNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "CON", "PRN", "AUX", "NUL",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
    };

    /// <summary>
    /// Writes each certificate to its own file under <paramref name="directory"/>.
    /// </summary>
    /// <param name="certificates">Certificates to write, end-entity first.</param>
    /// <param name="directory">Destination directory, created if missing.</param>
    /// <param name="format">Output encoding: pem or der.</param>
    /// <param name="naming">Filename scheme.</param>
    /// <param name="force">Overwrite existing files instead of failing.</param>
    /// <param name="dryRun">Report the paths that would be written without writing.</param>
    /// <returns>The file paths written, or that would be written under a dry run.</returns>
    internal static List<string> ExportCertificates(
        IReadOnlyList<X509Certificate2> certificates,
        string directory,
        string format,
        string naming,
        bool force,
        bool dryRun)
    {
        var extension = format.Equals("pem", StringComparison.OrdinalIgnoreCase) ? ".pem" : ".cer";

        // Resolve and validate every path before writing anything, so a collision fails
        // the whole export rather than leaving a half-written directory behind.
        var paths = new List<string>();

        // Match the filesystem: on Linux two CNs differing only in case are distinct
        // files, so treating them as a collision would reject a valid export.
        var used = new HashSet<string>(OperatingSystem.IsWindows()
            ? StringComparer.OrdinalIgnoreCase
            : StringComparer.Ordinal);

        for (var index = 0; index < certificates.Count; index++)
        {
            var fileName = BuildFileName(certificates[index], index, naming, extension);

            if (!used.Add(fileName))
            {
                throw new ArgumentException(
                    $"Filename collision on '{fileName}' using --naming {naming}. " +
                    "Use a scheme that includes the thumbprint to keep certificates distinct.");
            }

            // GetFullPath normalizes and surfaces an over-long or malformed path here,
            // in the resolve pass, rather than partway through the write loop - which
            // is the half-written directory this two-pass structure exists to prevent.
            string fullPath;
            try
            {
                fullPath = Path.GetFullPath(Path.Combine(directory, fileName));
            }
            catch (PathTooLongException)
            {
                throw new ArgumentException(
                    $"The resulting path for '{fileName}' is too long. " +
                    "Use a shorter --save-dir, or --naming thumbprint for shorter filenames.");
            }

            // Checked under --dry-run too, so the preview reports the same failure the
            // real run would hit.
            if (!force && File.Exists(fullPath))
            {
                throw new ArgumentException(
                    $"File already exists: {fullPath}. Use --force to overwrite.");
            }

            paths.Add(fullPath);
        }

        if (dryRun)
        {
            return paths;
        }

        Directory.CreateDirectory(directory);

        for (var index = 0; index < certificates.Count; index++)
        {
            CertificateUtilities.WriteCertificateBytes(certificates[index].RawData, paths[index], format);
        }

        return paths;
    }

    private static string BuildFileName(X509Certificate2 certificate, int index, string naming, string extension)
    {
        var thumbprint = certificate.Thumbprint ?? string.Empty;
        var shortThumbprint = thumbprint.Length >= 8 ? thumbprint[..8] : thumbprint;
        var commonName = SanitizeForFileName(CertificateUtilities.ExtractDnComponent(certificate.Subject));

        // Certificates without a usable CN fall back to the thumbprint, which every
        // certificate has. Observed on real roots that carry only OU= and O=.
        //
        // A reserved device name takes the same fallback: "CN=NUL" would otherwise
        // resolve to the device rather than a file, so File.Exists reports false, the
        // --force guard never fires, and the write disappears while reporting success.
        if (string.IsNullOrEmpty(commonName) || ReservedDeviceNames.Contains(commonName))
        {
            commonName = thumbprint;
        }

        var baseName = naming.ToLowerInvariant() switch
        {
            "thumbprint" => thumbprint,
            "cn" => commonName,
            "cn-thumbprint" => $"{commonName}-{shortThumbprint}",
            _ => $"{index:D2}-{commonName}-{shortThumbprint}"
        };

        return baseName + extension;
    }

    /// <summary>
    /// Reduces a certificate-supplied name to a safe single path segment.
    /// </summary>
    /// <remarks>
    /// The subject is attacker-controlled content, so a CN such as "..\..\evil" must not
    /// steer the write outside the target directory. Replacing the invalid characters and
    /// both separators is what neutralizes traversal; the GetFileName call is a second
    /// line of defense in case that set is ever narrowed.
    /// </remarks>
    private static string SanitizeForFileName(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var sanitized = value;
        foreach (var invalid in Path.GetInvalidFileNameChars())
        {
            sanitized = sanitized.Replace(invalid, '_');
        }

        // GetInvalidFileNameChars is platform-specific and omits '\' on Unix, so do not
        // rely on it alone to neutralize traversal.
        sanitized = sanitized.Replace('/', '_').Replace('\\', '_');
        sanitized = Path.GetFileName(sanitized);

        // A name of dots alone would still resolve to a directory reference.
        if (sanitized.Trim('.').Length == 0)
        {
            return string.Empty;
        }

        return sanitized.Trim();
    }
}
