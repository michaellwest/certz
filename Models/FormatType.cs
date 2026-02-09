namespace certz.Models;

/// <summary>
/// Represents certificate file formats.
/// </summary>
public enum FormatType
{
    /// <summary>
    /// PEM format (Base64 with BEGIN/END headers).
    /// </summary>
    Pem,

    /// <summary>
    /// DER format (Binary ASN.1 encoding).
    /// </summary>
    Der,

    /// <summary>
    /// PFX/PKCS#12 format (Password-protected bundle).
    /// </summary>
    Pfx,

    /// <summary>
    /// Format could not be determined.
    /// </summary>
    Unknown
}
