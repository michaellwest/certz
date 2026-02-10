namespace certz.Models;

/// <summary>
/// Result of a trust store operation (add or remove).
/// </summary>
internal record TrustOperationResult
{
    /// <summary>
    /// Whether the operation was successful.
    /// </summary>
    public required bool Success { get; init; }

    /// <summary>
    /// The type of operation performed.
    /// </summary>
    public required TrustOperationType Operation { get; init; }

    /// <summary>
    /// The name of the certificate store.
    /// </summary>
    public required string StoreName { get; init; }

    /// <summary>
    /// The location of the certificate store.
    /// </summary>
    public required string StoreLocation { get; init; }

    /// <summary>
    /// Information about certificates affected by the operation.
    /// </summary>
    public required List<TrustCertificateInfo> Certificates { get; init; }

    /// <summary>
    /// Error message if operation failed.
    /// </summary>
    public string? ErrorMessage { get; init; }
}

/// <summary>
/// The type of trust operation.
/// </summary>
internal enum TrustOperationType
{
    Add,
    Remove
}

/// <summary>
/// Information about a certificate in a trust operation.
/// </summary>
internal record TrustCertificateInfo
{
    /// <summary>
    /// The certificate subject.
    /// </summary>
    public required string Subject { get; init; }

    /// <summary>
    /// The certificate thumbprint.
    /// </summary>
    public required string Thumbprint { get; init; }

    /// <summary>
    /// When the certificate expires.
    /// </summary>
    public required DateTime NotAfter { get; init; }
}
