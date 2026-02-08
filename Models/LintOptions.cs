namespace certz.Models;

/// <summary>
/// Options for the lint command.
/// </summary>
internal record LintOptions
{
    /// <summary>
    /// The source to lint (file path, URL, or thumbprint).
    /// </summary>
    public required string Source { get; init; }

    /// <summary>
    /// Password for PFX files.
    /// </summary>
    public string? Password { get; init; }

    /// <summary>
    /// Policy set to validate against: "cabf" (default), "mozilla", "dev", or "all".
    /// </summary>
    public string PolicySet { get; init; } = "cabf";

    /// <summary>
    /// Minimum severity to report.
    /// </summary>
    public LintSeverity MinSeverity { get; init; } = LintSeverity.Info;

    /// <summary>
    /// Certificate store name for thumbprint lookup (My, Root, CA).
    /// </summary>
    public string? StoreName { get; init; }

    /// <summary>
    /// Store location (CurrentUser or LocalMachine).
    /// </summary>
    public string? StoreLocation { get; init; }
}
