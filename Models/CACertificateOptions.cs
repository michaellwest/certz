namespace certz.Models;

internal record CACertificateOptions
{
    public required string Name { get; init; }
    public int Days { get; init; } = 3650;
    public int PathLength { get; init; } = -1;
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

    // Extension URLs
    public string? CrlUrl { get; init; }
    public string? OcspUrl { get; init; }
    public string? CAIssuersUrl { get; init; }

    // Subject DN fields
    public string? SubjectO { get; init; }
    public string? SubjectOU { get; init; }
    public string? SubjectC { get; init; }
    public string? SubjectST { get; init; }
    public string? SubjectL { get; init; }
}
