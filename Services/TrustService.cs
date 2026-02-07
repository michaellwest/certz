using System.Runtime.Versioning;
using System.Security.Principal;
using certz.Models;

namespace certz.Services;

/// <summary>
/// Service for managing certificates in Windows certificate stores.
/// Provides operations for adding, removing, and listing certificates.
/// </summary>
internal static class TrustService
{
    /// <summary>
    /// Adds a certificate to the specified trust store.
    /// </summary>
    /// <param name="options">Options for adding the certificate.</param>
    /// <returns>Result of the operation.</returns>
    /// <exception cref="FileNotFoundException">Thrown when the certificate file is not found.</exception>
    /// <exception cref="InvalidOperationException">Thrown when administrator privileges are required.</exception>
    [SupportedOSPlatform("windows")]
    internal static TrustOperationResult AddToTrustStore(AddToTrustStoreOptions options)
    {
        if (!options.CertificateFile.Exists)
        {
            throw new FileNotFoundException($"Certificate file not found: {options.CertificateFile.FullName}");
        }

        // Check admin requirement for LocalMachine
        if (options.StoreLocation == StoreLocation.LocalMachine && !IsRunningAsAdmin())
        {
            throw new InvalidOperationException(
                "Administrator privileges required to modify LocalMachine certificate store. " +
                "Run the command as Administrator, or use '--location CurrentUser' for user-level trust.");
        }

        return TrustHandler.AddToStore(
            options.CertificateFile.FullName,
            options.Password,
            options.StoreName.ToString(),
            options.StoreLocation.ToString());
    }

    /// <summary>
    /// Removes certificates from the specified store.
    /// </summary>
    /// <param name="options">Options for removing certificates.</param>
    /// <returns>Result of the operation containing information about removed certificates.</returns>
    /// <exception cref="InvalidOperationException">Thrown when administrator privileges are required.</exception>
    [SupportedOSPlatform("windows")]
    internal static TrustOperationResult RemoveFromTrustStore(RemoveCertificateOptions options)
    {
        // Check admin requirement for LocalMachine
        if (options.StoreLocation == StoreLocation.LocalMachine && !IsRunningAsAdmin())
        {
            throw new InvalidOperationException(
                "Administrator privileges required to modify LocalMachine certificate store. " +
                "Run the command as Administrator, or use '--location CurrentUser' for user-level trust.");
        }

        var subject = options.Subject;
        var thumbprint = options.Thumbprint;

        // Normalize subject to include CN= prefix if needed
        if (!string.IsNullOrEmpty(subject) && !subject.StartsWith("CN="))
        {
            subject = $"CN={subject}";
        }

        // Build predicate for matching certificates
        bool predicate(X509Certificate2 c) =>
            (!string.IsNullOrEmpty(thumbprint) && c.Thumbprint.Equals(thumbprint, StringComparison.InvariantCultureIgnoreCase)) ||
            (!string.IsNullOrEmpty(subject) && c.Subject.Equals(subject, StringComparison.InvariantCultureIgnoreCase));

        var removedCertificates = new List<TrustCertificateInfo>();

        using var store = new X509Store(options.StoreName, options.StoreLocation, OpenFlags.ReadWrite);
        foreach (var certificate in store.Certificates.Where(predicate))
        {
            removedCertificates.Add(new TrustCertificateInfo
            {
                Subject = certificate.Subject,
                Thumbprint = certificate.Thumbprint,
                NotAfter = certificate.NotAfter
            });
            store.Remove(certificate);
        }
        store.Close();

        return new TrustOperationResult
        {
            Success = true,
            Operation = TrustOperationType.Remove,
            StoreName = options.StoreName.ToString(),
            StoreLocation = options.StoreLocation.ToString(),
            Certificates = removedCertificates
        };
    }

    /// <summary>
    /// Lists certificates from a certificate store.
    /// </summary>
    /// <param name="options">Options for listing certificates.</param>
    /// <returns>Result containing the list of certificates.</returns>
    internal static StoreListResult ListCertificates(ListCertificatesOptions options)
    {
        var storeListOptions = new StoreListOptions
        {
            StoreName = options.StoreName.ToString(),
            StoreLocation = options.StoreLocation.ToString(),
            ShowExpired = false,
            ExpiringDays = null
        };

        return StoreListHandler.ListCertificates(storeListOptions);
    }

    /// <summary>
    /// Checks if the current process is running with administrator privileges.
    /// </summary>
    [SupportedOSPlatform("windows")]
    private static bool IsRunningAsAdmin()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }
}
