namespace certz.Models;

/// <summary>
/// Options for showing certificate information from a file.
/// </summary>
internal record ShowCertificateInfoFromFileOptions
{
    /// <summary>
    /// The certificate file (PFX or PEM).
    /// </summary>
    public required FileInfo File { get; init; }

    /// <summary>
    /// Password for PFX files.
    /// </summary>
    public string? Password { get; init; }
}
