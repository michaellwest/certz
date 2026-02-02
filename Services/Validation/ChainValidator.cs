namespace certz.Services.Validation;

/// <summary>
/// Service for building and validating certificate chains.
/// </summary>
internal interface IChainValidator
{
    /// <summary>
    /// Validates a certificate chain.
    /// </summary>
    /// <param name="certificate">The end-entity certificate to validate.</param>
    /// <param name="checkRevocation">Whether to check certificate revocation status (OCSP preferred, CRL fallback).</param>
    /// <returns>The chain validation result including all chain elements and status.</returns>
    ChainValidationResult ValidateChain(X509Certificate2 certificate, bool checkRevocation = false);

    /// <summary>
    /// Validates a certificate chain with additional certificates.
    /// </summary>
    /// <param name="certificate">The end-entity certificate to validate.</param>
    /// <param name="additionalCertificates">Additional certificates to include in chain building.</param>
    /// <param name="checkRevocation">Whether to check certificate revocation status (OCSP preferred, CRL fallback).</param>
    /// <returns>The chain validation result including all chain elements and status.</returns>
    ChainValidationResult ValidateChain(X509Certificate2 certificate, X509Certificate2Collection additionalCertificates, bool checkRevocation = false);
}

/// <summary>
/// Default implementation of certificate chain validation.
/// </summary>
internal class ChainValidator : IChainValidator
{
    public ChainValidationResult ValidateChain(X509Certificate2 certificate, bool checkRevocation = false)
    {
        return ValidateChain(certificate, new X509Certificate2Collection(), checkRevocation);
    }

    public ChainValidationResult ValidateChain(X509Certificate2 certificate, X509Certificate2Collection additionalCertificates, bool checkRevocation = false)
    {
        using var chain = new X509Chain();

        // OCSP preferred, CRL fallback - .NET handles this automatically with Online mode
        // It checks OCSP first (via AIA extension), falls back to CRL if OCSP unavailable
        chain.ChainPolicy.RevocationMode = checkRevocation
            ? X509RevocationMode.Online
            : X509RevocationMode.NoCheck;
        chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;

        // Allow unknown CA to still build chain for self-signed or private CA certificates
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;

        // Set reasonable timeout for revocation checks (10 seconds)
        chain.ChainPolicy.UrlRetrievalTimeout = TimeSpan.FromSeconds(10);

        // Add any additional certificates to help build the chain
        if (additionalCertificates.Count > 0)
        {
            chain.ChainPolicy.ExtraStore.AddRange(additionalCertificates);
        }

        var isValid = chain.Build(certificate);

        var chainElements = new List<ChainElement>();
        foreach (var element in chain.ChainElements)
        {
            chainElements.Add(new ChainElement
            {
                Certificate = element.Certificate,
                Status = element.ChainElementStatus.ToList()
            });
        }

        return new ChainValidationResult
        {
            IsValid = isValid,
            ChainElements = chainElements,
            ChainStatus = chain.ChainStatus.ToList()
        };
    }
}

/// <summary>
/// Result of certificate chain validation.
/// </summary>
internal record ChainValidationResult
{
    /// <summary>
    /// Whether the chain is valid.
    /// </summary>
    public bool IsValid { get; init; }

    /// <summary>
    /// The chain elements from end-entity to root.
    /// </summary>
    public List<ChainElement> ChainElements { get; init; } = [];

    /// <summary>
    /// Overall chain status flags.
    /// </summary>
    public List<X509ChainStatus> ChainStatus { get; init; } = [];
}

/// <summary>
/// Information about a single element in the certificate chain.
/// </summary>
internal record ChainElement
{
    /// <summary>
    /// The certificate at this chain position.
    /// </summary>
    public required X509Certificate2 Certificate { get; init; }

    /// <summary>
    /// Status flags for this chain element.
    /// </summary>
    public List<X509ChainStatus> Status { get; init; } = [];
}
