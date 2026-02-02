namespace certz.Models;

internal record DevCertificateOptions
{
    public required string Domain { get; init; }
    public string[] AdditionalSANs { get; init; } = Array.Empty<string>();
    public int Days { get; init; } = 90;
    public string KeyType { get; init; } = "ECDSA-P256";
    public int KeySize { get; init; } = 3072;
    public string HashAlgorithm { get; init; } = "auto";
    public string RsaPadding { get; init; } = "pss";
    public string PfxEncryption { get; init; } = "modern";

    // Output options
    public FileInfo? PfxFile { get; init; }
    public FileInfo? CertFile { get; init; }
    public FileInfo? KeyFile { get; init; }
    public string? Password { get; init; }
    public FileInfo? PasswordFile { get; init; }

    // Trust options
    public bool Trust { get; init; }
    public StoreLocation TrustLocation { get; init; } = StoreLocation.CurrentUser;

    // Issuer options
    public FileInfo? IssuerCert { get; init; }
    public FileInfo? IssuerKey { get; init; }
    public string? IssuerPassword { get; init; }

    // Subject DN fields
    public string? SubjectO { get; init; }
    public string? SubjectOU { get; init; }
    public string? SubjectC { get; init; }
    public string? SubjectST { get; init; }
    public string? SubjectL { get; init; }
}
