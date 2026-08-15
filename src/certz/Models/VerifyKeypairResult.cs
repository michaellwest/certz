namespace certz.Models;

internal record VerifyKeypairResult
{
    public required bool Match { get; init; }
    public required string CertSource { get; init; }
    public required string KeySource { get; init; }
    public required string Subject { get; init; }
    public required string Algorithm { get; init; }
    public int? KeySize { get; init; }
    public required string CertPublicKeyHash { get; init; }
    public required string KeyPublicKeyHash { get; init; }
}
