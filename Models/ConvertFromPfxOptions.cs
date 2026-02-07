namespace certz.Models;

/// <summary>
/// Options for converting a PFX file to PEM format.
/// </summary>
internal record ConvertFromPfxOptions
{
    /// <summary>
    /// The PFX file to convert.
    /// </summary>
    public required FileInfo PfxFile { get; init; }

    /// <summary>
    /// Password for the PFX file.
    /// </summary>
    public required string Password { get; init; }

    /// <summary>
    /// Optional output file for the certificate (PEM format).
    /// </summary>
    public FileInfo? OutputCert { get; init; }

    /// <summary>
    /// Optional output file for the private key (PEM format).
    /// </summary>
    public FileInfo? OutputKey { get; init; }
}
