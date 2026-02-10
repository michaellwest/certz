namespace certz.Models;

/// <summary>
/// Result of monitoring certificates for expiration.
/// </summary>
internal record MonitorResult
{
    /// <summary>
    /// Total number of certificates scanned.
    /// </summary>
    public int TotalScanned { get; init; }

    /// <summary>
    /// Number of certificates expiring within threshold.
    /// </summary>
    public int ExpiringCount { get; init; }

    /// <summary>
    /// Number of expired certificates.
    /// </summary>
    public int ExpiredCount { get; init; }

    /// <summary>
    /// Number of valid certificates outside threshold.
    /// </summary>
    public int ValidCount { get; init; }

    /// <summary>
    /// Warning threshold used (in days).
    /// </summary>
    public int WarnThreshold { get; init; }

    /// <summary>
    /// Individual certificate results.
    /// </summary>
    public List<MonitoredCertificate> Certificates { get; init; } = [];

    /// <summary>
    /// Any errors encountered during scanning.
    /// </summary>
    public List<MonitorError> Errors { get; init; } = [];
}

/// <summary>
/// Information about a monitored certificate.
/// </summary>
internal record MonitoredCertificate
{
    /// <summary>
    /// Source of the certificate (file path, URL, store).
    /// </summary>
    public required string Source { get; init; }

    /// <summary>
    /// Certificate subject.
    /// </summary>
    public required string Subject { get; init; }

    /// <summary>
    /// Certificate thumbprint.
    /// </summary>
    public required string Thumbprint { get; init; }

    /// <summary>
    /// Expiration date.
    /// </summary>
    public required DateTime NotAfter { get; init; }

    /// <summary>
    /// Days remaining until expiration.
    /// </summary>
    public int DaysRemaining { get; init; }

    /// <summary>
    /// Status: Valid, Expiring, Expired, NotYetValid.
    /// </summary>
    public required string Status { get; init; }

    /// <summary>
    /// Whether certificate is within warning threshold.
    /// </summary>
    public bool IsWarning { get; init; }
}

/// <summary>
/// Error encountered during monitoring.
/// </summary>
internal record MonitorError
{
    /// <summary>
    /// Source that caused the error.
    /// </summary>
    public required string Source { get; init; }

    /// <summary>
    /// Error message.
    /// </summary>
    public required string Message { get; init; }
}
