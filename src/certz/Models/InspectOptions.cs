namespace certz.Models;

/// <summary>
/// Options for the inspect command.
/// </summary>
internal record InspectOptions
{
    /// <summary>
    /// The source to inspect (file path, URL, or thumbprint).
    /// </summary>
    public required string Source { get; init; }

    /// <summary>
    /// Password for PFX files.
    /// </summary>
    public string? Password { get; init; }

    /// <summary>
    /// Whether to show the certificate chain.
    /// </summary>
    public bool ShowChain { get; init; }

    /// <summary>
    /// Whether to show detailed tree with key info, SANs, and signatures (requires ShowChain).
    /// </summary>
    public bool DetailedTree { get; init; }

    /// <summary>
    /// Whether to check certificate revocation status (OCSP/CRL).
    /// </summary>
    public bool CheckCrl { get; init; }

    /// <summary>
    /// Warn if certificate expires within N days.
    /// </summary>
    public int? WarnDays { get; init; }

    /// <summary>
    /// Path to save the certificate to.
    /// </summary>
    public string? SavePath { get; init; }

    /// <summary>
    /// Path to save the private key to.
    /// </summary>
    public string? SaveKeyPath { get; init; }

    /// <summary>
    /// Export format (pem or der).
    /// </summary>
    public string SaveFormat { get; init; } = "pem";

    /// <summary>
    /// Directory to write each chain certificate to, one file per certificate.
    /// </summary>
    public string? SaveDir { get; init; }

    /// <summary>
    /// Whether a chain must be built. Exporting needs one even when the caller only
    /// asked for files, so this is kept separate from ShowChain, which governs display.
    /// </summary>
    public bool NeedsChain => ShowChain || !string.IsNullOrEmpty(SaveDir);

    /// <summary>
    /// Filename scheme used by SaveDir.
    /// </summary>
    public string Naming { get; init; } = "index-cn-thumbprint";

    /// <summary>
    /// Whether SaveDir may overwrite existing files.
    /// </summary>
    public bool Force { get; init; }

    /// <summary>
    /// Whether SaveDir should report planned paths without writing.
    /// </summary>
    public bool DryRun { get; init; }

    /// <summary>
    /// Certificate store name for thumbprint lookup (My, Root, CA).
    /// </summary>
    public string? StoreName { get; init; }

    /// <summary>
    /// Store location (CurrentUser or LocalMachine).
    /// </summary>
    public string? StoreLocation { get; init; }
}
