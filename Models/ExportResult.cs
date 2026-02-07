namespace certz.Models;

/// <summary>
/// Result of a certificate export operation.
/// </summary>
internal record ExportResult
{
    /// <summary>
    /// Whether the export was successful.
    /// </summary>
    public required bool Success { get; init; }

    /// <summary>
    /// Certificate subject.
    /// </summary>
    public required string Subject { get; init; }

    /// <summary>
    /// Certificate issuer.
    /// </summary>
    public required string Issuer { get; init; }

    /// <summary>
    /// Certificate thumbprint.
    /// </summary>
    public required string Thumbprint { get; init; }

    /// <summary>
    /// Certificate expiration date.
    /// </summary>
    public required DateTime NotAfter { get; init; }

    /// <summary>
    /// Source of the certificate (URL or store location).
    /// </summary>
    public required string Source { get; init; }

    /// <summary>
    /// Output files that were created.
    /// </summary>
    public string[] OutputFiles { get; init; } = Array.Empty<string>();

    /// <summary>
    /// The generated password (if one was generated for PFX).
    /// </summary>
    public string? GeneratedPassword { get; init; }

    /// <summary>
    /// Whether a password was automatically generated.
    /// </summary>
    public bool PasswordWasGenerated { get; init; }
}
