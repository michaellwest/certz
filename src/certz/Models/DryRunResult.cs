namespace certz.Models;

/// <summary>
/// A key/value detail line in a dry-run preview.
/// </summary>
internal record DryRunDetail(string Key, string Value);

/// <summary>
/// Result of a --dry-run preview.  No files are written or modified.
/// </summary>
internal record DryRunResult
{
    /// <summary>
    /// The certz command being previewed (e.g. "create dev", "trust add").
    /// </summary>
    public required string Command { get; init; }

    /// <summary>
    /// Human-readable description of the action that would be taken.
    /// </summary>
    public required string Action { get; init; }

    /// <summary>
    /// Ordered list of property/value pairs describing what would happen.
    /// </summary>
    public required DryRunDetail[] Details { get; init; }

    /// <summary>
    /// True when the provided options are valid and the operation would succeed.
    /// </summary>
    public bool WouldSucceed { get; init; } = true;
}
