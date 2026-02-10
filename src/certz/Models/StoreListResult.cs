namespace certz.Models;

/// <summary>
/// Result of listing certificates from a certificate store.
/// </summary>
internal record StoreListResult
{
    /// <summary>
    /// The name of the certificate store.
    /// </summary>
    public required string StoreName { get; init; }

    /// <summary>
    /// The location of the certificate store.
    /// </summary>
    public required string StoreLocation { get; init; }

    /// <summary>
    /// The certificates in the store.
    /// </summary>
    public required List<StoreCertificateInfo> Certificates { get; init; }

    /// <summary>
    /// Total number of certificates in the store (before filtering).
    /// </summary>
    public required int TotalCount { get; init; }

    /// <summary>
    /// Number of certificates matching the filter criteria.
    /// </summary>
    public required int FilteredCount { get; init; }
}

/// <summary>
/// Information about a certificate in a store listing.
/// </summary>
internal record StoreCertificateInfo
{
    /// <summary>
    /// The certificate subject.
    /// </summary>
    public required string Subject { get; init; }

    /// <summary>
    /// The certificate issuer.
    /// </summary>
    public required string Issuer { get; init; }

    /// <summary>
    /// The certificate thumbprint (SHA-1 hash).
    /// </summary>
    public required string Thumbprint { get; init; }

    /// <summary>
    /// When the certificate becomes valid.
    /// </summary>
    public required DateTime NotBefore { get; init; }

    /// <summary>
    /// When the certificate expires.
    /// </summary>
    public required DateTime NotAfter { get; init; }

    /// <summary>
    /// Days remaining until expiration.
    /// </summary>
    public required int DaysRemaining { get; init; }

    /// <summary>
    /// Whether this certificate has expired.
    /// </summary>
    public required bool IsExpired { get; init; }

    /// <summary>
    /// Whether this certificate has a private key.
    /// </summary>
    public required bool HasPrivateKey { get; init; }

    /// <summary>
    /// Whether this certificate is a Certificate Authority.
    /// </summary>
    public required bool IsCa { get; init; }
}
