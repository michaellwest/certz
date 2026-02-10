namespace certz.Models;

/// <summary>
/// Options for listing certificates from a store.
/// </summary>
internal record StoreListOptions
{
    /// <summary>
    /// The name of the certificate store (My, Root, CA, etc.).
    /// </summary>
    public string? StoreName { get; init; }

    /// <summary>
    /// The location of the certificate store (CurrentUser or LocalMachine).
    /// </summary>
    public string? StoreLocation { get; init; }

    /// <summary>
    /// Show only expired certificates.
    /// </summary>
    public bool ShowExpired { get; init; }

    /// <summary>
    /// Show certificates expiring within N days.
    /// </summary>
    public int? ExpiringDays { get; init; }
}
