namespace certz.Models;

/// <summary>
/// Options for verifying a certificate from a file.
/// </summary>
internal record VerifyFromFileOptions
{
    /// <summary>
    /// The certificate file (PFX or PEM).
    /// </summary>
    public required FileInfo File { get; init; }

    /// <summary>
    /// Password for PFX files.
    /// </summary>
    public string? Password { get; init; }

    /// <summary>
    /// Whether to check certificate revocation status.
    /// </summary>
    public bool CheckRevocation { get; init; }

    /// <summary>
    /// Number of days before expiration to show warning.
    /// </summary>
    public int WarningDays { get; init; } = 30;
}
