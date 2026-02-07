namespace certz.Models;

/// <summary>
/// Result of a certificate verification operation.
/// </summary>
internal record CertificateVerificationResult
{
    /// <summary>
    /// Whether the certificate passed all validation checks.
    /// </summary>
    public required bool Success { get; init; }

    /// <summary>
    /// Certificate subject.
    /// </summary>
    public required string Subject { get; init; }

    /// <summary>
    /// Certificate thumbprint.
    /// </summary>
    public required string Thumbprint { get; init; }

    /// <summary>
    /// Expiration check result.
    /// </summary>
    public required ExpirationCheckResult ExpirationCheck { get; init; }

    /// <summary>
    /// Chain validation result.
    /// </summary>
    public required ChainValidationResult ChainValidation { get; init; }

    /// <summary>
    /// Trust check result.
    /// </summary>
    public required TrustCheckResult TrustCheck { get; init; }

    /// <summary>
    /// Revocation check result (only if revocation checking was requested).
    /// </summary>
    public RevocationCheckResult? RevocationCheck { get; init; }
}

/// <summary>
/// Result of the expiration check.
/// </summary>
internal record ExpirationCheckResult
{
    /// <summary>
    /// Whether the expiration check passed.
    /// </summary>
    public required bool Passed { get; init; }

    /// <summary>
    /// Certificate expiration date.
    /// </summary>
    public required DateTime NotAfter { get; init; }

    /// <summary>
    /// Days remaining until expiration (negative if expired).
    /// </summary>
    public required int DaysRemaining { get; init; }

    /// <summary>
    /// Whether the certificate is expired.
    /// </summary>
    public required bool IsExpired { get; init; }

    /// <summary>
    /// Whether the certificate is not yet valid.
    /// </summary>
    public required bool IsNotYetValid { get; init; }

    /// <summary>
    /// Whether the certificate is expiring soon (within warning threshold).
    /// </summary>
    public required bool IsExpiringSoon { get; init; }

    /// <summary>
    /// Warning threshold in days.
    /// </summary>
    public int WarningThreshold { get; init; }

    /// <summary>
    /// Status message.
    /// </summary>
    public string? Message { get; init; }
}

/// <summary>
/// Result of the chain validation check.
/// </summary>
internal record ChainValidationResult
{
    /// <summary>
    /// Whether the chain validation passed.
    /// </summary>
    public required bool Passed { get; init; }

    /// <summary>
    /// Chain elements (from end-entity to root).
    /// </summary>
    public required List<string> ChainElements { get; init; }

    /// <summary>
    /// Chain validation errors (if any).
    /// </summary>
    public List<string> Errors { get; init; } = [];
}

/// <summary>
/// Result of the trust check.
/// </summary>
internal record TrustCheckResult
{
    /// <summary>
    /// Whether the trust check passed.
    /// </summary>
    public required bool Passed { get; init; }

    /// <summary>
    /// Whether the root certificate is trusted.
    /// </summary>
    public bool IsTrusted { get; init; }

    /// <summary>
    /// Root certificate subject (if available).
    /// </summary>
    public string? RootSubject { get; init; }

    /// <summary>
    /// Status message.
    /// </summary>
    public string? Message { get; init; }
}

/// <summary>
/// Result of the revocation check.
/// </summary>
internal record RevocationCheckResult
{
    /// <summary>
    /// Whether the revocation check passed.
    /// </summary>
    public required bool Passed { get; init; }

    /// <summary>
    /// Whether the certificate is revoked.
    /// </summary>
    public bool IsRevoked { get; init; }

    /// <summary>
    /// Whether revocation status could not be checked (offline).
    /// </summary>
    public bool IsOffline { get; init; }

    /// <summary>
    /// Status message.
    /// </summary>
    public string? Message { get; init; }
}
