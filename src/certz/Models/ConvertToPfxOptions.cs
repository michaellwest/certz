namespace certz.Models;

/// <summary>
/// Options for converting PEM certificate and key files to PFX format.
/// </summary>
internal record ConvertToPfxOptions
{
    /// <summary>
    /// The PEM certificate file to convert.
    /// </summary>
    public required FileInfo CertFile { get; init; }

    /// <summary>
    /// The PEM private key file to convert.
    /// </summary>
    public required FileInfo KeyFile { get; init; }

    /// <summary>
    /// The output PFX file path.
    /// </summary>
    public required FileInfo OutputFile { get; init; }

    /// <summary>
    /// Password for the PFX file. If not provided, a secure password will be generated.
    /// </summary>
    public string? Password { get; init; }

    /// <summary>
    /// Optional file to save the password to.
    /// </summary>
    public FileInfo? PasswordFile { get; init; }

    /// <summary>
    /// PFX encryption mode: "modern" (AES-256-CBC) or "legacy" (3DES).
    /// </summary>
    public string PfxEncryption { get; init; } = "modern";
}
