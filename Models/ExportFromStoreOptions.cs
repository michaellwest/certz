namespace certz.Models;

/// <summary>
/// Options for exporting a certificate from a certificate store.
/// </summary>
internal record ExportFromStoreOptions
{
    /// <summary>
    /// Thumbprint of the certificate to export.
    /// </summary>
    public required string Thumbprint { get; init; }

    /// <summary>
    /// Store name (My, Root, CA, etc.).
    /// </summary>
    public StoreName StoreName { get; init; } = StoreName.My;

    /// <summary>
    /// Store location (CurrentUser or LocalMachine).
    /// </summary>
    public StoreLocation StoreLocation { get; init; } = StoreLocation.CurrentUser;

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
    /// Password for the PFX file. If not provided and PFX is requested, a secure password will be generated.
    /// </summary>
    public string? Password { get; init; }

    /// <summary>
    /// Optional file to save the password to.
    /// </summary>
    public FileInfo? PasswordFile { get; init; }
}
