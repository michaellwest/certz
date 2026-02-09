namespace certz.Models;

internal record CertificateCreationResult
{
    public required string Subject { get; init; }
    public required string Thumbprint { get; init; }
    public required DateTime NotBefore { get; init; }
    public required DateTime NotAfter { get; init; }
    public required string KeyType { get; init; }
    public string[] SANs { get; init; } = Array.Empty<string>();
    public string[] OutputFiles { get; init; } = Array.Empty<string>();
    public string? Password { get; init; }
    public bool PasswordWasGenerated { get; init; }
    public bool WasTrusted { get; init; }
    public bool IsCA { get; init; }
    public int PathLength { get; init; } = -1;

    /// <summary>
    /// Indicates the certificate was generated in ephemeral mode (not persisted).
    /// </summary>
    public bool IsEphemeral { get; init; }

    /// <summary>
    /// Indicates output was piped to stdout.
    /// </summary>
    public bool WasPiped { get; init; }
}
