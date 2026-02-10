namespace certz.Models;

/// <summary>
/// Options for the renew command.
/// </summary>
internal record RenewOptions
{
    /// <summary>
    /// Source certificate (file path or thumbprint).
    /// </summary>
    public required string Source { get; init; }

    /// <summary>
    /// New validity period in days. Null preserves original duration.
    /// </summary>
    public int? Days { get; init; }

    /// <summary>
    /// Password for source PFX file.
    /// </summary>
    public string? Password { get; init; }

    /// <summary>
    /// Output file path.
    /// </summary>
    public FileInfo? OutputFile { get; init; }

    /// <summary>
    /// Password for output file.
    /// </summary>
    public string? OutputPassword { get; init; }

    /// <summary>
    /// Preserve existing private key instead of generating new.
    /// </summary>
    public bool KeepKey { get; init; }

    /// <summary>
    /// Issuer certificate for signing (required for CA-signed certs).
    /// </summary>
    public FileInfo? IssuerCert { get; init; }

    /// <summary>
    /// Issuer private key file (PEM format).
    /// </summary>
    public FileInfo? IssuerKey { get; init; }

    /// <summary>
    /// Password for issuer PFX.
    /// </summary>
    public string? IssuerPassword { get; init; }

    /// <summary>
    /// Certificate store name for thumbprint lookup.
    /// </summary>
    public string? StoreName { get; init; }

    /// <summary>
    /// Store location (CurrentUser, LocalMachine).
    /// </summary>
    public string? StoreLocation { get; init; }
}
