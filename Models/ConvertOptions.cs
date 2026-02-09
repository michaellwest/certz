namespace certz.Models;

/// <summary>
/// Options for the simplified convert command.
/// </summary>
internal record ConvertOptions
{
    /// <summary>
    /// Input certificate file.
    /// </summary>
    public required FileInfo InputFile { get; init; }

    /// <summary>
    /// Detected format of the input file.
    /// </summary>
    public FormatType InputFormat { get; init; }

    /// <summary>
    /// Target output format.
    /// </summary>
    public required FormatType OutputFormat { get; init; }

    /// <summary>
    /// Output file path (null for auto-generated).
    /// </summary>
    public FileInfo? OutputFile { get; init; }

    /// <summary>
    /// Private key file (for PFX output when input lacks key).
    /// </summary>
    public FileInfo? KeyFile { get; init; }

    /// <summary>
    /// Password for PFX input/output.
    /// </summary>
    public string? Password { get; init; }

    /// <summary>
    /// File to read/write password.
    /// </summary>
    public FileInfo? PasswordFile { get; init; }

    /// <summary>
    /// PFX encryption mode: modern or legacy.
    /// </summary>
    public string PfxEncryption { get; init; } = "modern";

    /// <summary>
    /// Whether to include private key in output.
    /// </summary>
    public bool IncludeKey { get; init; } = true;
}
