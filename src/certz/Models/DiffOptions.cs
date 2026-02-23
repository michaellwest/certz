namespace certz.Models;

/// <summary>
/// Options for the diff command.
/// </summary>
internal record DiffOptions
{
    /// <summary>
    /// The first source to compare (file path, URL, or thumbprint).
    /// </summary>
    public required string Source1 { get; init; }

    /// <summary>
    /// The second source to compare (file path, URL, or thumbprint).
    /// </summary>
    public required string Source2 { get; init; }

    /// <summary>
    /// Password for the first source (PFX files).
    /// </summary>
    public string? Password1 { get; init; }

    /// <summary>
    /// Password for the second source (PFX files).
    /// </summary>
    public string? Password2 { get; init; }

    /// <summary>
    /// Certificate store name for the first source (My, Root, CA).
    /// </summary>
    public string? StoreName1 { get; init; }

    /// <summary>
    /// Certificate store name for the second source (My, Root, CA).
    /// </summary>
    public string? StoreName2 { get; init; }

    /// <summary>
    /// Store location for the first source (CurrentUser or LocalMachine).
    /// </summary>
    public string? StoreLocation1 { get; init; }

    /// <summary>
    /// Store location for the second source (CurrentUser or LocalMachine).
    /// </summary>
    public string? StoreLocation2 { get; init; }
}
