namespace certz.Models;

/// <summary>
/// Options for listing certificates from a certificate store.
/// </summary>
internal record ListCertificatesOptions
{
    /// <summary>
    /// Store name (My, Root, CA, etc.).
    /// </summary>
    public StoreName StoreName { get; init; } = StoreName.My;

    /// <summary>
    /// Store location (CurrentUser or LocalMachine).
    /// </summary>
    public StoreLocation StoreLocation { get; init; } = StoreLocation.CurrentUser;
}
