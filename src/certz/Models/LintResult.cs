namespace certz.Models;

/// <summary>
/// Severity level for lint findings.
/// </summary>
internal enum LintSeverity
{
    Info = 0,
    Warning = 1,
    Error = 2
}

/// <summary>
/// A single lint finding from certificate validation.
/// </summary>
internal record LintFinding
{
    /// <summary>
    /// Rule identifier (e.g., "BR-001", "NSS-001").
    /// </summary>
    public required string RuleId { get; init; }

    /// <summary>
    /// Human-readable rule name.
    /// </summary>
    public required string RuleName { get; init; }

    /// <summary>
    /// Severity of the finding.
    /// </summary>
    public required LintSeverity Severity { get; init; }

    /// <summary>
    /// Detailed message explaining the issue.
    /// </summary>
    public required string Message { get; init; }

    /// <summary>
    /// Policy source (e.g., "CA/B Forum BR", "Mozilla NSS", "Development").
    /// </summary>
    public required string Policy { get; init; }

    /// <summary>
    /// Actual value found in the certificate.
    /// </summary>
    public string? ActualValue { get; init; }

    /// <summary>
    /// Expected or required value.
    /// </summary>
    public string? ExpectedValue { get; init; }
}

/// <summary>
/// Result of linting a certificate against industry standards.
/// </summary>
internal record LintResult
{
    /// <summary>
    /// The certificate subject (Distinguished Name).
    /// </summary>
    public required string Subject { get; init; }

    /// <summary>
    /// The certificate thumbprint.
    /// </summary>
    public required string Thumbprint { get; init; }

    /// <summary>
    /// Whether all checks passed (no errors).
    /// </summary>
    public required bool Passed { get; init; }

    /// <summary>
    /// All lint findings from validation.
    /// </summary>
    public required List<LintFinding> Findings { get; init; }

    /// <summary>
    /// Count of error-level findings.
    /// </summary>
    public int ErrorCount => Findings.Count(f => f.Severity == LintSeverity.Error);

    /// <summary>
    /// Count of warning-level findings.
    /// </summary>
    public int WarningCount => Findings.Count(f => f.Severity == LintSeverity.Warning);

    /// <summary>
    /// Count of informational findings.
    /// </summary>
    public int InfoCount => Findings.Count(f => f.Severity == LintSeverity.Info);

    /// <summary>
    /// The policy set used for validation.
    /// </summary>
    public required string PolicySet { get; init; }

    /// <summary>
    /// Whether this is a CA certificate.
    /// </summary>
    public bool IsCa { get; init; }

    /// <summary>
    /// Whether this is a self-signed (root) certificate.
    /// </summary>
    public bool IsRoot { get; init; }

    /// <summary>
    /// Source path of the certificate.
    /// </summary>
    public string? SourcePath { get; init; }
}
