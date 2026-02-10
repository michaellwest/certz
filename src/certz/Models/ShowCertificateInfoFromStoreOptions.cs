namespace certz.Models;

/// <summary>
/// Options for showing certificate information from a certificate store.
/// </summary>
internal record ShowCertificateInfoFromStoreOptions
{
    /// <summary>
    /// Thumbprint of the certificate to show.
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
}
