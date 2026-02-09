namespace certz.Models;

/// <summary>
/// Result of a certificate conversion operation.
/// </summary>
internal record ConversionResult
{
    /// <summary>
    /// Whether the conversion was successful.
    /// </summary>
    public required bool Success { get; init; }

    /// <summary>
    /// The output file path.
    /// </summary>
    public required string OutputFile { get; init; }

    /// <summary>
    /// The input certificate file path (for PEM to PFX conversion).
    /// </summary>
    public string? InputCertificate { get; init; }

    /// <summary>
    /// The input key file path (for PEM to PFX conversion).
    /// </summary>
    public string? InputKey { get; init; }

    /// <summary>
    /// The input PFX file path (for PFX to PEM conversion).
    /// </summary>
    public string? InputPfx { get; init; }

    /// <summary>
    /// The generated password (if one was generated).
    /// </summary>
    public string? GeneratedPassword { get; init; }

    /// <summary>
    /// Whether a password was automatically generated.
    /// </summary>
    public bool PasswordWasGenerated { get; init; }

    /// <summary>
    /// Additional output files created (e.g., certificate and key files in PFX to PEM conversion).
    /// </summary>
    public string[] AdditionalOutputFiles { get; init; } = Array.Empty<string>();

    /// <summary>
    /// Certificate subject (for display purposes).
    /// </summary>
    public string? Subject { get; init; }

    /// <summary>
    /// The output format (PEM, DER, PFX).
    /// </summary>
    public string? OutputFormat { get; init; }
}
