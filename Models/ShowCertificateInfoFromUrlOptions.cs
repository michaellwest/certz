namespace certz.Models;

/// <summary>
/// Options for showing certificate information from a URL.
/// </summary>
internal record ShowCertificateInfoFromUrlOptions
{
    /// <summary>
    /// The URL to connect to and retrieve the certificate from.
    /// </summary>
    public required Uri Url { get; init; }
}
