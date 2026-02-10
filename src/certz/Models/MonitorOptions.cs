namespace certz.Models;

/// <summary>
/// Options for the monitor command.
/// </summary>
internal record MonitorOptions
{
    /// <summary>
    /// Sources to scan (files, directories, URLs).
    /// </summary>
    public required string[] Sources { get; init; }

    /// <summary>
    /// Warning threshold in days.
    /// </summary>
    public int WarnDays { get; init; } = 30;

    /// <summary>
    /// Scan subdirectories recursively.
    /// </summary>
    public bool Recursive { get; init; }

    /// <summary>
    /// Password for PFX files.
    /// </summary>
    public string? Password { get; init; }

    /// <summary>
    /// Certificate store name to scan.
    /// </summary>
    public string? StoreName { get; init; }

    /// <summary>
    /// Store location (CurrentUser, LocalMachine).
    /// </summary>
    public string? StoreLocation { get; init; }

    /// <summary>
    /// Only output certificates within warning threshold.
    /// </summary>
    public bool QuietMode { get; init; }

    /// <summary>
    /// Exit with code 1 if certificates within warning threshold.
    /// </summary>
    public bool FailOnWarning { get; init; }
}
