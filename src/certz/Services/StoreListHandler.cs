using certz.Models;

namespace certz.Services;

/// <summary>
/// Service for listing certificates from certificate stores.
/// </summary>
internal static class StoreListHandler
{
    /// <summary>
    /// Lists certificates from the specified store.
    /// </summary>
    public static StoreListResult ListCertificates(StoreListOptions options)
    {
        var location = ParseStoreLocation(options.StoreLocation);
        var name = ParseStoreName(options.StoreName);

        using var store = new X509Store(name, location);
        store.Open(OpenFlags.ReadOnly);

        var now = DateTime.Now;
        var certificates = new List<StoreCertificateInfo>();
        var totalCount = store.Certificates.Count;

        foreach (var cert in store.Certificates)
        {
            var daysRemaining = (cert.NotAfter - now).Days;
            var isExpired = cert.NotAfter < now;

            // Apply filters
            if (options.ShowExpired && !isExpired)
            {
                continue;
            }

            if (options.ExpiringDays.HasValue && !isExpired && daysRemaining > options.ExpiringDays.Value)
            {
                continue;
            }

            // Get basic constraints
            var basicConstraints = cert.Extensions["2.5.29.19"] as X509BasicConstraintsExtension;
            var isCa = basicConstraints?.CertificateAuthority ?? false;

            certificates.Add(new StoreCertificateInfo
            {
                Subject = cert.Subject,
                Issuer = cert.Issuer,
                Thumbprint = cert.Thumbprint,
                NotBefore = cert.NotBefore,
                NotAfter = cert.NotAfter,
                DaysRemaining = daysRemaining,
                IsExpired = isExpired,
                HasPrivateKey = cert.HasPrivateKey,
                IsCa = isCa
            });
        }

        // Sort by expiration date (soonest first)
        certificates.Sort((a, b) => a.NotAfter.CompareTo(b.NotAfter));

        return new StoreListResult
        {
            StoreName = name.ToString(),
            StoreLocation = location.ToString(),
            Certificates = certificates,
            TotalCount = totalCount,
            FilteredCount = certificates.Count
        };
    }

    /// <summary>
    /// Parses the store location string to a StoreLocation enum.
    /// </summary>
    internal static StoreLocation ParseStoreLocation(string? location)
    {
        return location?.ToLowerInvariant() switch
        {
            "localmachine" => StoreLocation.LocalMachine,
            "currentuser" or null or "" => StoreLocation.CurrentUser,
            _ => StoreLocation.CurrentUser
        };
    }

    /// <summary>
    /// Parses the store name string to a StoreName enum.
    /// </summary>
    internal static StoreName ParseStoreName(string? storeName)
    {
        return storeName?.ToLowerInvariant() switch
        {
            "root" => StoreName.Root,
            "ca" or "certificateauthority" => StoreName.CertificateAuthority,
            "trustedpeople" => StoreName.TrustedPeople,
            "trustedpublisher" => StoreName.TrustedPublisher,
            "disallowed" => StoreName.Disallowed,
            "addressbook" => StoreName.AddressBook,
            "authroot" => StoreName.AuthRoot,
            "my" or null or "" => StoreName.My,
            _ => StoreName.My
        };
    }
}
