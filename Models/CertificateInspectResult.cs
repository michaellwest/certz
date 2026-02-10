namespace certz.Models;

/// <summary>
/// Result of inspecting a certificate, containing all relevant details.
/// </summary>
internal record CertificateInspectResult
{
    /// <summary>
    /// The certificate subject (Distinguished Name).
    /// </summary>
    public required string Subject { get; init; }

    /// <summary>
    /// The certificate issuer (Distinguished Name).
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
    /// Days until the certificate expires (negative if already expired).
    /// </summary>
    public required int DaysRemaining { get; init; }

    /// <summary>
    /// The key algorithm (RSA, ECDSA, etc.).
    /// </summary>
    public required string KeyAlgorithm { get; init; }

    /// <summary>
    /// The key size in bits.
    /// </summary>
    public required int KeySize { get; init; }

    /// <summary>
    /// The signature algorithm used to sign the certificate.
    /// </summary>
    public required string SignatureAlgorithm { get; init; }

    /// <summary>
    /// Subject Alternative Names (DNS names, IP addresses, URIs).
    /// </summary>
    public required List<string> SubjectAlternativeNames { get; init; }

    /// <summary>
    /// Key Usage values (e.g., Digital Signature, Key Encipherment).
    /// </summary>
    public required List<string> KeyUsages { get; init; }

    /// <summary>
    /// Enhanced Key Usage values (e.g., Server Authentication, Client Authentication).
    /// </summary>
    public required List<string> EnhancedKeyUsages { get; init; }

    /// <summary>
    /// Whether this certificate is a Certificate Authority.
    /// </summary>
    public required bool IsCa { get; init; }

    /// <summary>
    /// Path length constraint for CA certificates (-1 if not set or not a CA).
    /// </summary>
    public int? PathLengthConstraint { get; init; }

    /// <summary>
    /// Whether the certificate has an associated private key.
    /// </summary>
    public required bool HasPrivateKey { get; init; }

    /// <summary>
    /// The source of the certificate (File, URL, or Store).
    /// </summary>
    public InspectSource Source { get; init; }

    /// <summary>
    /// The source path, URL, or store location.
    /// </summary>
    public string? SourcePath { get; init; }

    /// <summary>
    /// Certificate chain information (if --chain was specified).
    /// </summary>
    public List<ChainElementInfo>? Chain { get; init; }

    /// <summary>
    /// Whether the certificate chain is valid.
    /// </summary>
    public bool ChainIsValid { get; init; }

    /// <summary>
    /// Whether to display detailed tree view (with key info, SANs, signatures).
    /// </summary>
    public bool DetailedTree { get; init; }

    /// <summary>
    /// Any warnings or issues found during inspection.
    /// </summary>
    public List<string> Warnings { get; init; } = [];
}
