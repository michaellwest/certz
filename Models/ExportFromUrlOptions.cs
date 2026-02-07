namespace certz.Models;

/// <summary>
/// Options for exporting a certificate from a remote URL.
/// </summary>
internal record ExportFromUrlOptions
{
    /// <summary>
    /// The URL to connect to and retrieve the certificate from.
    /// </summary>
    public required Uri Url { get; init; }

    /// <summary>
    /// Optional output file for the PFX.
    /// </summary>
    public FileInfo? PfxFile { get; init; }

    /// <summary>
    /// Optional output file for the certificate (PEM format).
    /// </summary>
    public FileInfo? CertFile { get; init; }

    /// <summary>
    /// Optional output file for the private key (PEM format).
    /// </summary>
    public FileInfo? KeyFile { get; init; }

    /// <summary>
    /// Password for the PFX file. If not provided, a secure password will be generated.
    /// </summary>
    public string? Password { get; init; }

    /// <summary>
    /// Optional file to save the password to.
    /// </summary>
    public FileInfo? PasswordFile { get; init; }
}
