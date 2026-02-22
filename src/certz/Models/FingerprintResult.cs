namespace certz.Models;

internal record FingerprintResult
{
    public required string Algorithm { get; init; }
    public required string Fingerprint { get; init; }
    public required string Source { get; init; }
    public required string Subject { get; init; }
}
