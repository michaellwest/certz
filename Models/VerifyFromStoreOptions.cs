namespace certz.Models;

/// <summary>
/// Options for verifying a certificate from a certificate store.
/// </summary>
internal record VerifyFromStoreOptions
{
    /// <summary>
    /// Thumbprint of the certificate to verify.
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
    /// Whether to check certificate revocation status.
    /// </summary>
    public bool CheckRevocation { get; init; }

    /// <summary>
    /// Number of days before expiration to show warning.
    /// </summary>
    public int WarningDays { get; init; } = 30;
}
