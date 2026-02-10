namespace certz.Models;

/// <summary>
/// Indicates the source type for certificate inspection.
/// </summary>
internal enum InspectSource
{
    /// <summary>
    /// Certificate was loaded from a file (PFX, PEM, DER, etc.).
    /// </summary>
    File,

    /// <summary>
    /// Certificate was retrieved from a remote HTTPS URL.
    /// </summary>
    Url,

    /// <summary>
    /// Certificate was loaded from a certificate store by thumbprint.
    /// </summary>
    Store
}
