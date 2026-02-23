namespace certz.Models;

/// <summary>
/// Status of a single field in a certificate diff.
/// </summary>
internal enum DiffFieldStatus
{
    Unchanged,
    Changed
}

/// <summary>
/// A single field comparison between two certificates.
/// </summary>
internal record CertDiffField(
    string Name,
    string LeftValue,
    string RightValue,
    DiffFieldStatus Status);

/// <summary>
/// Result of comparing two certificates field by field.
/// </summary>
internal record DiffResult
{
    /// <summary>
    /// The first source (file path, URL, or store path).
    /// </summary>
    public required string Source1 { get; init; }

    /// <summary>
    /// The second source (file path, URL, or store path).
    /// </summary>
    public required string Source2 { get; init; }

    /// <summary>
    /// Field-by-field comparison results.
    /// </summary>
    public required List<CertDiffField> Fields { get; init; }

    /// <summary>
    /// True when all fields are unchanged (certificates are identical).
    /// </summary>
    public bool AreIdentical => Fields.All(f => f.Status == DiffFieldStatus.Unchanged);

    /// <summary>
    /// Number of fields that differ between the two certificates.
    /// </summary>
    public int DifferenceCount => Fields.Count(f => f.Status == DiffFieldStatus.Changed);
}
