namespace certz.Models;

/// <summary>
/// Options for adding a certificate to a trust store.
/// </summary>
internal record AddToTrustStoreOptions
{
    /// <summary>
    /// Path to the certificate file to add.
    /// </summary>
    public required FileInfo CertificateFile { get; init; }

    /// <summary>
    /// Password for the certificate file (if PFX/P12).
    /// </summary>
    public string? Password { get; init; }

    /// <summary>
    /// Store name (My, Root, CA, etc.).
    /// </summary>
    public StoreName StoreName { get; init; } = StoreName.Root;

    /// <summary>
    /// Store location (CurrentUser or LocalMachine).
    /// </summary>
    public StoreLocation StoreLocation { get; init; } = StoreLocation.CurrentUser;
}
