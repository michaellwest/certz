namespace certz.Models;

/// <summary>
/// Options for removing a certificate from a certificate store.
/// </summary>
internal record RemoveCertificateOptions
{
    /// <summary>
    /// Subject of the certificate to remove. Multiple certificates may match.
    /// </summary>
    public string? Subject { get; init; }

    /// <summary>
    /// Thumbprint of the certificate to remove.
    /// </summary>
    public string? Thumbprint { get; init; }

    /// <summary>
    /// Store name (My, Root, CA, etc.).
    /// </summary>
    public StoreName StoreName { get; init; } = StoreName.My;

    /// <summary>
    /// Store location (CurrentUser or LocalMachine).
    /// </summary>
    public StoreLocation StoreLocation { get; init; } = StoreLocation.CurrentUser;
}
