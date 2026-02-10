namespace certz.Models;

/// <summary>
/// Result of certificate renewal operation.
/// </summary>
internal record RenewResult
{
    /// <summary>
    /// Whether the renewal succeeded.
    /// </summary>
    public bool Success { get; init; }

    /// <summary>
    /// Error message if renewal failed.
    /// </summary>
    public string? ErrorMessage { get; init; }

    // Original certificate info
    /// <summary>
    /// Subject of the original certificate.
    /// </summary>
    public required string OriginalSubject { get; init; }

    /// <summary>
    /// Thumbprint of the original certificate.
    /// </summary>
    public required string OriginalThumbprint { get; init; }

    /// <summary>
    /// Expiration date of the original certificate.
    /// </summary>
    public required DateTime OriginalNotAfter { get; init; }

    // Renewed certificate info
    /// <summary>
    /// Subject of the renewed certificate.
    /// </summary>
    public string? NewSubject { get; init; }

    /// <summary>
    /// Thumbprint of the renewed certificate.
    /// </summary>
    public string? NewThumbprint { get; init; }

    /// <summary>
    /// Start date of the renewed certificate.
    /// </summary>
    public DateTime? NewNotBefore { get; init; }

    /// <summary>
    /// Expiration date of the renewed certificate.
    /// </summary>
    public DateTime? NewNotAfter { get; init; }

    /// <summary>
    /// Path to the output file.
    /// </summary>
    public string? OutputFile { get; init; }

    /// <summary>
    /// Password for the output file (if generated).
    /// </summary>
    public string? Password { get; init; }

    /// <summary>
    /// Whether the password was auto-generated.
    /// </summary>
    public bool PasswordWasGenerated { get; init; }

    // Detected parameters (for display)
    /// <summary>
    /// Subject Alternative Names from the certificate.
    /// </summary>
    public string[]? SANs { get; init; }

    /// <summary>
    /// Key algorithm used.
    /// </summary>
    public string? KeyType { get; init; }

    /// <summary>
    /// Whether the original key was preserved.
    /// </summary>
    public bool KeyWasPreserved { get; init; }

    /// <summary>
    /// Whether the cert was re-signed by a CA.
    /// </summary>
    public bool WasResigned { get; init; }
}
