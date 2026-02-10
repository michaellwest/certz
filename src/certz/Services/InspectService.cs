using certz.Models;

namespace certz.Services;

/// <summary>
/// Service for inspecting and verifying certificates from various sources.
/// Consolidates certificate inspection and verification operations.
/// </summary>
internal static class InspectService
{
    /// <summary>
    /// Inspects a certificate from a file.
    /// </summary>
    /// <param name="options">Options for showing certificate information.</param>
    /// <returns>Result containing the certificate details.</returns>
    internal static CertificateInspectResult InspectFile(ShowCertificateInfoFromFileOptions options)
    {
        var inspectOptions = new InspectOptions
        {
            Source = options.File.FullName,
            Password = options.Password,
            ShowChain = false,
            CheckCrl = false
        };

        return CertificateInspector.InspectFile(inspectOptions);
    }

    /// <summary>
    /// Inspects a certificate from a URL.
    /// </summary>
    /// <param name="options">Options for showing certificate information.</param>
    /// <returns>Result containing the certificate details.</returns>
    internal static async Task<CertificateInspectResult> InspectUrl(ShowCertificateInfoFromUrlOptions options)
    {
        var inspectOptions = new InspectOptions
        {
            Source = options.Url.ToString(),
            ShowChain = false,
            CheckCrl = false
        };

        return await CertificateInspector.InspectUrlAsync(inspectOptions);
    }

    /// <summary>
    /// Inspects a certificate from a certificate store.
    /// </summary>
    /// <param name="options">Options for showing certificate information.</param>
    /// <returns>Result containing the certificate details.</returns>
    internal static CertificateInspectResult InspectStore(ShowCertificateInfoFromStoreOptions options)
    {
        var inspectOptions = new InspectOptions
        {
            Source = options.Thumbprint,
            StoreName = options.StoreName.ToString(),
            StoreLocation = options.StoreLocation.ToString(),
            ShowChain = false,
            CheckCrl = false
        };

        return CertificateInspector.InspectFromStore(inspectOptions);
    }

    /// <summary>
    /// Verifies a certificate from a file.
    /// </summary>
    /// <param name="options">Options for verifying the certificate.</param>
    /// <returns>Result containing the verification details.</returns>
    /// <exception cref="FileNotFoundException">Thrown when the certificate file is not found.</exception>
    /// <exception cref="ArgumentException">Thrown when password is required but not provided.</exception>
    internal static async Task<CertificateVerificationResult> VerifyFile(VerifyFromFileOptions options)
    {
        if (!options.File.Exists)
        {
            throw new FileNotFoundException($"Certificate file not found: {options.File.FullName}");
        }

        X509Certificate2? certificate = null;

        if (options.File.Extension.Equals(".pfx", StringComparison.OrdinalIgnoreCase) ||
            options.File.Extension.Equals(".p12", StringComparison.OrdinalIgnoreCase))
        {
            if (string.IsNullOrEmpty(options.Password))
            {
                throw new ArgumentException("Password is required to load PFX file. Use --password to specify the password.");
            }
            certificate = X509CertificateLoader.LoadPkcs12FromFile(
                options.File.FullName,
                options.Password,
                X509KeyStorageFlags.Exportable
            );
        }
        else
        {
            var certificateText = await File.ReadAllTextAsync(options.File.FullName);
            certificate = X509Certificate2.CreateFromPem(certificateText);
        }

        try
        {
            return PerformVerification(certificate, options.CheckRevocation, options.WarningDays);
        }
        finally
        {
            certificate.Dispose();
        }
    }

    /// <summary>
    /// Verifies a certificate from a certificate store.
    /// </summary>
    /// <param name="options">Options for verifying the certificate.</param>
    /// <returns>Result containing the verification details.</returns>
    /// <exception cref="CertificateException">Thrown when the certificate is not found.</exception>
    internal static CertificateVerificationResult VerifyStore(VerifyFromStoreOptions options)
    {
        using var store = new X509Store(options.StoreName, options.StoreLocation, OpenFlags.ReadOnly);
        var certificate = store.Certificates
            .FirstOrDefault(c => c.Thumbprint.Equals(options.Thumbprint, StringComparison.InvariantCultureIgnoreCase));

        if (certificate == null)
        {
            throw new CertificateException($"Certificate with thumbprint {options.Thumbprint} not found in {options.StoreLocation}\\{options.StoreName}");
        }

        try
        {
            return PerformVerification(certificate, options.CheckRevocation, options.WarningDays);
        }
        finally
        {
            store.Close();
        }
    }

    private static CertificateVerificationResult PerformVerification(X509Certificate2 certificate, bool checkRevocation, int warningDays)
    {
        var now = DateTime.Now;
        var allChecksPassed = true;

        // 1. Expiration Check
        var expirationCheck = CheckExpiration(certificate, now, warningDays, ref allChecksPassed);

        // 2. Chain Validation
        var chainValidation = ValidateChain(certificate, checkRevocation, ref allChecksPassed);

        // 3. Trust Check
        var trustCheck = CheckTrust(chainValidation, ref allChecksPassed);

        // 4. Revocation Check (if requested)
        RevocationCheckResult? revocationCheck = null;
        if (checkRevocation)
        {
            revocationCheck = CheckRevocation(chainValidation, ref allChecksPassed);
        }

        return new CertificateVerificationResult
        {
            Success = allChecksPassed,
            Subject = certificate.SubjectName.Format(false),
            Thumbprint = certificate.Thumbprint,
            ExpirationCheck = expirationCheck,
            ChainValidation = chainValidation,
            TrustCheck = trustCheck,
            RevocationCheck = revocationCheck
        };
    }

    private static ExpirationCheckResult CheckExpiration(X509Certificate2 certificate, DateTime now, int warningDays, ref bool allChecksPassed)
    {
        var daysRemaining = (certificate.NotAfter - now).Days;
        var isExpired = certificate.NotAfter < now;
        var isNotYetValid = certificate.NotBefore > now;
        var isExpiringSoon = !isExpired && !isNotYetValid && daysRemaining <= warningDays;
        var passed = !isExpired && !isNotYetValid;

        string? message = null;
        if (isExpired)
        {
            message = $"Certificate has EXPIRED on {certificate.NotAfter:yyyy-MM-dd}. Expired {(now - certificate.NotAfter).Days} days ago.";
            allChecksPassed = false;
        }
        else if (isNotYetValid)
        {
            message = $"Certificate is NOT YET VALID (starts {certificate.NotBefore:yyyy-MM-dd}).";
            allChecksPassed = false;
        }
        else if (isExpiringSoon)
        {
            message = $"Certificate expires SOON on {certificate.NotAfter:yyyy-MM-dd} ({daysRemaining} days remaining). Warning threshold: {warningDays} days.";
        }
        else
        {
            message = $"Certificate is valid until {certificate.NotAfter:yyyy-MM-dd} ({daysRemaining} days remaining).";
        }

        return new ExpirationCheckResult
        {
            Passed = passed,
            NotAfter = certificate.NotAfter,
            DaysRemaining = daysRemaining,
            IsExpired = isExpired,
            IsNotYetValid = isNotYetValid,
            IsExpiringSoon = isExpiringSoon,
            WarningThreshold = warningDays,
            Message = message
        };
    }

    private static ChainValidationResult ValidateChain(X509Certificate2 certificate, bool checkRevocation, ref bool allChecksPassed)
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = checkRevocation
            ? X509RevocationMode.Online
            : X509RevocationMode.NoCheck;
        chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;

        var chainIsValid = chain.Build(certificate);

        var chainElements = new List<string>();
        for (int i = 0; i < chain.ChainElements.Count; i++)
        {
            var element = chain.ChainElements[i];
            chainElements.Add(element.Certificate.Subject);
        }

        var errors = new List<string>();
        if (!chainIsValid)
        {
            allChecksPassed = false;
            foreach (var status in chain.ChainStatus)
            {
                errors.Add($"{status.Status}: {status.StatusInformation}");
            }
        }

        return new ChainValidationResult
        {
            Passed = chainIsValid,
            ChainElements = chainElements,
            Errors = errors
        };
    }

    private static TrustCheckResult CheckTrust(ChainValidationResult chainValidation, ref bool allChecksPassed)
    {
        if (chainValidation.Passed && chainValidation.ChainElements.Count > 0)
        {
            var rootSubject = chainValidation.ChainElements[^1];

            using var rootStore = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
            rootStore.Open(OpenFlags.ReadOnly);

            var trustedRoot = rootStore.Certificates
                .Cast<X509Certificate2>()
                .Any(c => c.Subject.Equals(rootSubject, StringComparison.Ordinal));

            rootStore.Close();

            if (trustedRoot)
            {
                return new TrustCheckResult
                {
                    Passed = true,
                    IsTrusted = true,
                    RootSubject = rootSubject,
                    Message = "Certificate chains to a trusted root."
                };
            }
            else
            {
                return new TrustCheckResult
                {
                    Passed = true,
                    IsTrusted = false,
                    RootSubject = rootSubject,
                    Message = $"Root certificate is not in trusted store. Root: {rootSubject}"
                };
            }
        }
        else
        {
            allChecksPassed = false;
            return new TrustCheckResult
            {
                Passed = false,
                Message = "Cannot verify trust (chain validation failed)."
            };
        }
    }

    private static RevocationCheckResult CheckRevocation(ChainValidationResult chainValidation, ref bool allChecksPassed)
    {
        if (!chainValidation.Passed)
        {
            return new RevocationCheckResult
            {
                Passed = false,
                Message = "Revocation status cannot be checked (chain validation failed)."
            };
        }

        var errors = chainValidation.Errors;
        var revokedError = errors.FirstOrDefault(e => e.Contains("Revoked"));
        if (revokedError != null)
        {
            allChecksPassed = false;
            return new RevocationCheckResult
            {
                Passed = false,
                IsRevoked = true,
                Message = "Certificate has been REVOKED."
            };
        }

        var offlineError = errors.FirstOrDefault(e => e.Contains("OfflineRevocation"));
        if (offlineError != null)
        {
            return new RevocationCheckResult
            {
                Passed = true,
                IsOffline = true,
                Message = "Revocation status could not be checked (offline)."
            };
        }

        return new RevocationCheckResult
        {
            Passed = true,
            Message = "Certificate has not been revoked."
        };
    }
}
