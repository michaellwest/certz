namespace certz.Models;

/// <summary>
/// Information about a single element in a certificate chain, suitable for serialization.
/// </summary>
internal record ChainElementInfo
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
    /// The certificate serial number.
    /// </summary>
    public required string SerialNumber { get; init; }

    /// <summary>
    /// When the certificate becomes valid.
    /// </summary>
    public required DateTime NotBefore { get; init; }

    /// <summary>
    /// When the certificate expires.
    /// </summary>
    public required DateTime NotAfter { get; init; }

    /// <summary>
    /// Whether this certificate is a Certificate Authority.
    /// </summary>
    public required bool IsCa { get; init; }

    /// <summary>
    /// Whether this certificate is self-signed (Subject equals Issuer).
    /// </summary>
    public required bool IsSelfSigned { get; init; }

    /// <summary>
    /// Any validation errors for this chain element.
    /// </summary>
    public List<string> ValidationErrors { get; init; } = [];
}
