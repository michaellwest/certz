namespace certz.Services;

internal static class CertificateDisplay
{
    internal static void WriteRow(X509Certificate2 certificate)
    {
        var subject = certificate.SubjectName.Format(false);
        Console.WriteLine($"{certificate.Thumbprint}\t{subject}");
    }

    internal static void DisplayCertificateDetails(X509Certificate2 certificate)
    {
        Console.WriteLine("Certificate Information");
        Console.WriteLine("======================");
        Console.WriteLine();

        // Basic Information
        Console.WriteLine("Subject:              {0}", certificate.SubjectName.Format(false));
        Console.WriteLine("Issuer:               {0}", certificate.IssuerName.Format(false));
        Console.WriteLine("Thumbprint:           {0}", certificate.Thumbprint);
        Console.WriteLine("Serial Number:        {0}", certificate.SerialNumber);
        Console.WriteLine();

        // Validity Period
        Console.WriteLine("Validity Period");
        Console.WriteLine("---------------");
        Console.WriteLine("Not Before:           {0}", certificate.NotBefore.ToString("yyyy-MM-dd HH:mm:ss"));
        Console.WriteLine("Not After:            {0}", certificate.NotAfter.ToString("yyyy-MM-dd HH:mm:ss"));
        var daysRemaining = (certificate.NotAfter - DateTime.Now).Days;
        Console.WriteLine("Days Remaining:       {0}", daysRemaining > 0 ? daysRemaining : "EXPIRED");
        Console.WriteLine();

        // Public Key Information
        Console.WriteLine("Public Key");
        Console.WriteLine("----------");
        Console.WriteLine("Algorithm:            {0}", certificate.PublicKey.Oid.FriendlyName);

        // Get key size - handle different key types
        try
        {
            var rsa = certificate.GetRSAPublicKey();
            if (rsa != null)
            {
                Console.WriteLine("Key Size:             {0} bits", rsa.KeySize);
            }
            else
            {
                var ecdsa = certificate.GetECDsaPublicKey();
                if (ecdsa != null)
                {
                    Console.WriteLine("Key Size:             {0} bits", ecdsa.KeySize);
                }
                else
                {
                    Console.WriteLine("Key Size:             (Unable to determine)");
                }
            }
        }
        catch
        {
            Console.WriteLine("Key Size:             (Unable to determine)");
        }

        Console.WriteLine("Signature Algorithm:  {0}", certificate.SignatureAlgorithm.FriendlyName);
        Console.WriteLine();

        // Subject Alternative Names
        var sanExtension = certificate.Extensions
            .OfType<X509Extension>()
            .FirstOrDefault(e => e.Oid?.Value == "2.5.29.17");

        if (sanExtension != null)
        {
            Console.WriteLine("Subject Alternative Names");
            Console.WriteLine("------------------------");
            var asnData = new AsnEncodedData(sanExtension.Oid!, sanExtension.RawData);
            var sanString = asnData.Format(false);
            Console.WriteLine(sanString);
            Console.WriteLine();
        }

        // Enhanced Key Usage
        var ekuExtension = certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().FirstOrDefault();
        if (ekuExtension != null)
        {
            Console.WriteLine("Enhanced Key Usage");
            Console.WriteLine("------------------");
            foreach (var oid in ekuExtension.EnhancedKeyUsages)
            {
                Console.WriteLine(" - {0} ({1})", oid.FriendlyName, oid.Value);
            }
            Console.WriteLine();
        }

        // Key Usage
        var keyUsageExtension = certificate.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault();
        if (keyUsageExtension != null)
        {
            Console.WriteLine("Key Usage");
            Console.WriteLine("---------");
            Console.WriteLine(keyUsageExtension.KeyUsages.ToString());
            Console.WriteLine();
        }

        // Basic Constraints
        var basicConstraints = certificate.Extensions.OfType<X509BasicConstraintsExtension>().FirstOrDefault();
        if (basicConstraints != null)
        {
            Console.WriteLine("Basic Constraints");
            Console.WriteLine("----------------");
            Console.WriteLine("Certificate Authority: {0}", basicConstraints.CertificateAuthority ? "Yes" : "No");
            Console.WriteLine("Path Length Constraint: {0}", basicConstraints.HasPathLengthConstraint
                ? basicConstraints.PathLengthConstraint.ToString()
                : "None");
            Console.WriteLine();
        }

        // Private Key Status
        Console.WriteLine("Private Key:          {0}", certificate.HasPrivateKey ? "Present" : "Not Present");
    }

    internal static void DisplayValidationReport(X509Certificate2 certificate, bool checkRevocation, int warningDays)
    {
        Console.WriteLine("Certificate Validation Report");
        Console.WriteLine("============================");
        Console.WriteLine();
        Console.WriteLine("Certificate: {0}", certificate.SubjectName.Format(false));
        Console.WriteLine("Thumbprint:  {0}", certificate.Thumbprint);
        Console.WriteLine();

        var allChecksPassed = true;

        // 1. Expiration Check
        Console.WriteLine("[1] Checking Expiration Status...");
        var now = DateTime.Now;
        if (certificate.NotAfter < now)
        {
            Console.WriteLine("    [FAIL] Certificate has EXPIRED on {0}", certificate.NotAfter.ToString("yyyy-MM-dd"));
            Console.WriteLine("           Expired {0} days ago", (now - certificate.NotAfter).Days);
            allChecksPassed = false;
        }
        else if (certificate.NotBefore > now)
        {
            Console.WriteLine("    [FAIL] Certificate is NOT YET VALID (starts {0})", certificate.NotBefore.ToString("yyyy-MM-dd"));
            allChecksPassed = false;
        }
        else
        {
            var daysRemaining = (certificate.NotAfter - now).Days;
            if (daysRemaining <= warningDays)
            {
                Console.WriteLine("    [WARN] Certificate expires SOON on {0} ({1} days remaining)",
                    certificate.NotAfter.ToString("yyyy-MM-dd"), daysRemaining);
                Console.WriteLine("           Warning threshold: {0} days", warningDays);
            }
            else
            {
                Console.WriteLine("    [PASS] Certificate is valid");
                Console.WriteLine("           Valid until {0} ({1} days remaining)",
                    certificate.NotAfter.ToString("yyyy-MM-dd"), daysRemaining);
            }
        }
        Console.WriteLine();

        // 2. Chain Validation
        Console.WriteLine("[2] Checking Certificate Chain...");
        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = checkRevocation
            ? X509RevocationMode.Online
            : X509RevocationMode.NoCheck;
        chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;

        var chainIsValid = chain.Build(certificate);

        if (chainIsValid)
        {
            Console.WriteLine("    [PASS] Chain is valid");
            Console.WriteLine("           Chain length: {0} certificate(s)", chain.ChainElements.Count);

            for (int i = 0; i < chain.ChainElements.Count; i++)
            {
                var element = chain.ChainElements[i];
                var indent = new string(' ', 11 + (i * 2));
                Console.WriteLine("{0}{1}. {2}", indent, i + 1, element.Certificate.Subject);
            }
        }
        else
        {
            Console.WriteLine("    [FAIL] Chain validation failed");
            allChecksPassed = false;

            foreach (var status in chain.ChainStatus)
            {
                Console.WriteLine("           - {0}: {1}", status.Status, status.StatusInformation);
            }
        }
        Console.WriteLine();

        // 3. Trust Validation
        Console.WriteLine("[3] Checking Trust Status...");
        if (chainIsValid && chain.ChainElements.Count > 0)
        {
            var rootCert = chain.ChainElements[chain.ChainElements.Count - 1].Certificate;
            using var rootStore = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
            rootStore.Open(OpenFlags.ReadOnly);

            var trustedRoot = rootStore.Certificates
                .Cast<X509Certificate2>()
                .Any(c => c.Thumbprint.Equals(rootCert.Thumbprint, StringComparison.OrdinalIgnoreCase));

            rootStore.Close();

            if (trustedRoot)
            {
                Console.WriteLine("    [PASS] Certificate chains to a trusted root");
            }
            else
            {
                Console.WriteLine("    [WARN] Root certificate is not in trusted store");
                Console.WriteLine("           Root: {0}", rootCert.Subject);
            }
        }
        else
        {
            Console.WriteLine("    [FAIL] Cannot verify trust (chain validation failed)");
            allChecksPassed = false;
        }
        Console.WriteLine();

        // 4. Revocation Check (if requested)
        if (checkRevocation)
        {
            Console.WriteLine("[4] Checking Revocation Status...");
            var revocationStatus = chain.ChainStatus
                .FirstOrDefault(s => s.Status == X509ChainStatusFlags.Revoked);

            if (revocationStatus.Status == X509ChainStatusFlags.Revoked)
            {
                Console.WriteLine("    [FAIL] Certificate has been REVOKED");
                Console.WriteLine("           {0}", revocationStatus.StatusInformation);
                allChecksPassed = false;
            }
            else
            {
                var offlineRevocation = chain.ChainStatus
                    .FirstOrDefault(s => s.Status == X509ChainStatusFlags.OfflineRevocation);

                if (offlineRevocation.Status == X509ChainStatusFlags.OfflineRevocation)
                {
                    Console.WriteLine("    [WARN] Revocation status could not be checked (offline)");
                }
                else
                {
                    Console.WriteLine("    [PASS] Certificate has not been revoked");
                }
            }
            Console.WriteLine();
        }

        // Summary
        Console.WriteLine("Summary");
        Console.WriteLine("-------");
        if (allChecksPassed)
        {
            Console.WriteLine("[PASS] Certificate validation SUCCESSFUL");
            Console.WriteLine("        The certificate passed all validation checks.");
        }
        else
        {
            Console.WriteLine("[FAIL] Certificate validation FAILED");
            Console.WriteLine("        See details above for specific failures.");
        }
    }
}
