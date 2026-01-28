namespace certz.Services;

internal static class CertificateGeneration
{
    private const int RSAMinimumKeySizeInBits = 2048;
    private const string ServerAuthenticationEnhancedKeyUsageOid = "1.3.6.1.5.5.7.3.1";
    private const string ServerAuthenticationEnhancedKeyUsageOidFriendlyName = "Server Authentication";

    internal static X509Certificate2 GenerateCertificate(
        string[] dnsNames,
        DateTimeOffset notBefore,
        DateTimeOffset notAfter,
        int keySize = 2048,
        string hashAlgorithm = "auto",
        string keyType = "RSA",
        string rsaPadding = "pkcs1",
        bool isCA = false,
        int pathLength = -1,
        string? crlUrl = null,
        string? ocspUrl = null,
        string? caIssuersUrl = null,
        string? subjectO = null,
        string? subjectOU = null,
        string? subjectC = null,
        string? subjectST = null,
        string? subjectL = null)
    {
        // Build full Distinguished Name
        var subjectBuilder = new System.Text.StringBuilder();
        subjectBuilder.Append($"CN={dnsNames[0]}");
        if (!string.IsNullOrEmpty(subjectOU)) subjectBuilder.Append($", OU={subjectOU}");
        if (!string.IsNullOrEmpty(subjectO)) subjectBuilder.Append($", O={subjectO}");
        if (!string.IsNullOrEmpty(subjectL)) subjectBuilder.Append($", L={subjectL}");
        if (!string.IsNullOrEmpty(subjectST)) subjectBuilder.Append($", ST={subjectST}");
        if (!string.IsNullOrEmpty(subjectC)) subjectBuilder.Append($", C={subjectC}");

        var subject = new X500DistinguishedName(subjectBuilder.ToString());
        var extensions = new List<X509Extension>();
        var sanBuilder = new SubjectAlternativeNameBuilder();
        foreach (var dnsName in dnsNames)
        {
            if (IPAddress.TryParse(dnsName, out var ipAddress))
            {
                sanBuilder.AddIpAddress(ipAddress);
            }
            else
            {
                sanBuilder.AddDnsName(dnsName);
            }
        }

        // Determine hash algorithm (auto-select based on key size/type if not specified)
        var hashName = SelectHashAlgorithm(hashAlgorithm, keySize, keyType);

        // Create key material and certificate request based on key type
        CertificateRequest request;
        X509SubjectKeyIdentifierExtension subjectKeyIdentifier;

        keyType = keyType.ToUpperInvariant();
        if (keyType == "RSA")
        {
            var rsaKey = CreateRSAKeyMaterial(keySize);
            var padding = rsaPadding.ToUpperInvariant() == "PSS"
                ? RSASignaturePadding.Pss
                : RSASignaturePadding.Pkcs1;
            request = new CertificateRequest(subject, rsaKey, hashName, padding);
            subjectKeyIdentifier = new X509SubjectKeyIdentifierExtension(request.PublicKey, false);
        }
        else if (keyType.StartsWith("ECDSA-"))
        {
            var curveName = keyType.Substring(6); // Extract P256, P384, P521
            var ecdsaKey = CreateECDSAKeyMaterial(curveName);
            request = new CertificateRequest(subject, ecdsaKey, hashName);
            subjectKeyIdentifier = new X509SubjectKeyIdentifierExtension(request.PublicKey, false);
        }
        else
        {
            throw new ArgumentException($"Unsupported key type: {keyType}. Use RSA, ECDSA-P256, ECDSA-P384, or ECDSA-P521.");
        }

        // Authority Key Identifier - RFC 5280 Section 4.2.1.1 (MUST be included in all conforming CA certificates)
        // For self-signed certificates, AKI should match SKI
        var authorityKeyIdentifier = X509AuthorityKeyIdentifierExtension.CreateFromSubjectKeyIdentifier(subjectKeyIdentifier);

        // Key Usage - different for CA vs end-entity certificates
        X509KeyUsageExtension keyUsage;
        if (isCA)
        {
            // CA certificates: KeyCertSign, CrlSign, DigitalSignature
            keyUsage = new X509KeyUsageExtension(
                X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.DigitalSignature,
                critical: true);
        }
        else
        {
            // End-entity certificates: KeyEncipherment, DigitalSignature
            keyUsage = new X509KeyUsageExtension(
                X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.DigitalSignature,
                critical: true);
        }

        // Enhanced Key Usage - only for end-entity certificates (not CA)
        X509EnhancedKeyUsageExtension enhancedKeyUsage = null;
        if (!isCA)
        {
            enhancedKeyUsage = new X509EnhancedKeyUsageExtension(
                new OidCollection()
                {
                    new Oid(ServerAuthenticationEnhancedKeyUsageOid, ServerAuthenticationEnhancedKeyUsageOidFriendlyName)
                }, critical: false);
        }

        // Basic Constraints
        var basicConstraints = new X509BasicConstraintsExtension(
            isCA,
            pathLength >= 0,
            pathLength,
            true);

        // Determine if SAN should be critical: only when subject DN is empty or minimal (RFC 5280 Section 4.2.1.6)
        bool subjectIsMinimal = string.IsNullOrEmpty(dnsNames[0]) || dnsNames[0].Length < 3;

        extensions.Add(basicConstraints);
        extensions.Add(keyUsage);
        if (enhancedKeyUsage != null)
        {
            extensions.Add(enhancedKeyUsage);
        }
        extensions.Add(subjectKeyIdentifier);
        extensions.Add(authorityKeyIdentifier);
        extensions.Add(sanBuilder.Build(subjectIsMinimal));

        // CRL Distribution Points - RFC 5280 Section 4.2.1.13
        if (!string.IsNullOrEmpty(crlUrl))
        {
            var crlDistributionPoints = BuildCRLDistributionPointsExtension(crlUrl);
            extensions.Add(crlDistributionPoints);
        }

        // Authority Information Access - RFC 5280 Section 4.2.2.1
        if (!string.IsNullOrEmpty(ocspUrl) || !string.IsNullOrEmpty(caIssuersUrl))
        {
            var authorityInformationAccess = BuildAuthorityInformationAccessExtension(ocspUrl, caIssuersUrl);
            extensions.Add(authorityInformationAccess);
        }

        foreach (var extension in extensions)
        {
            request.CertificateExtensions.Add(extension);
        }

        var result = request.CreateSelfSigned(notBefore, notAfter);
        if (OperatingSystem.IsWindows())
        {
            result.FriendlyName = "certz";
        }
        return result;
    }

    private static HashAlgorithmName SelectHashAlgorithm(string hashAlgorithm, int keySize, string keyType)
    {
        hashAlgorithm = hashAlgorithm.ToUpperInvariant();

        if (hashAlgorithm != "AUTO")
        {
            return hashAlgorithm switch
            {
                "SHA256" => HashAlgorithmName.SHA256,
                "SHA384" => HashAlgorithmName.SHA384,
                "SHA512" => HashAlgorithmName.SHA512,
                _ => throw new ArgumentException($"Unsupported hash algorithm: {hashAlgorithm}")
            };
        }

        // Auto-select: align hash strength with key strength
        if (keyType.ToUpperInvariant().StartsWith("ECDSA"))
        {
            // For ECDSA, match hash to curve strength
            if (keyType.Contains("P521")) return HashAlgorithmName.SHA512;
            if (keyType.Contains("P384")) return HashAlgorithmName.SHA384;
            return HashAlgorithmName.SHA256; // P256
        }
        else
        {
            // For RSA, match hash to key size
            if (keySize >= 4096) return HashAlgorithmName.SHA512;
            if (keySize >= 3072) return HashAlgorithmName.SHA384;
            return HashAlgorithmName.SHA256; // 2048
        }
    }

    private static RSA CreateRSAKeyMaterial(int keySize)
    {
        if (keySize < RSAMinimumKeySizeInBits)
        {
            throw new ArgumentException($"RSA key size must be at least {RSAMinimumKeySizeInBits} bits");
        }

        var rsa = RSA.Create(keySize);
        if (rsa.KeySize < keySize)
        {
            throw new InvalidOperationException($"Failed to create an RSA key with a size of {keySize} bits");
        }

        return rsa;
    }

    private static ECDsa CreateECDSAKeyMaterial(string curveName)
    {
        var curve = curveName.ToUpperInvariant() switch
        {
            "P256" => ECCurve.NamedCurves.nistP256,
            "P384" => ECCurve.NamedCurves.nistP384,
            "P521" => ECCurve.NamedCurves.nistP521,
            _ => throw new ArgumentException($"Unsupported ECDSA curve: {curveName}. Use P256, P384, or P521.")
        };

        return ECDsa.Create(curve);
    }

    private static X509Extension BuildCRLDistributionPointsExtension(string crlUrl)
    {
        // CRL Distribution Points Extension - OID 2.5.29.31
        // ASN.1 Structure:
        // CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
        // DistributionPoint ::= SEQUENCE {
        //    distributionPoint [0] DistributionPointName OPTIONAL,
        //    ... }
        // DistributionPointName ::= CHOICE {
        //    fullName [0] GeneralNames,
        //    ... }
        // GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
        // GeneralName ::= CHOICE {
        //    uniformResourceIdentifier [6] IA5String,
        //    ... }

        var asnWriter = new System.Formats.Asn1.AsnWriter(System.Formats.Asn1.AsnEncodingRules.DER);
        using (asnWriter.PushSequence()) // CRLDistributionPoints SEQUENCE
        {
            using (asnWriter.PushSequence()) // DistributionPoint SEQUENCE
            {
                using (asnWriter.PushSequence(new System.Formats.Asn1.Asn1Tag(System.Formats.Asn1.TagClass.ContextSpecific, 0))) // [0] distributionPoint
                {
                    using (asnWriter.PushSequence(new System.Formats.Asn1.Asn1Tag(System.Formats.Asn1.TagClass.ContextSpecific, 0))) // [0] fullName
                    {
                        // [6] uniformResourceIdentifier
                        asnWriter.WriteCharacterString(
                            System.Formats.Asn1.UniversalTagNumber.IA5String,
                            crlUrl,
                            new System.Formats.Asn1.Asn1Tag(System.Formats.Asn1.TagClass.ContextSpecific, 6));
                    }
                }
            }
        }

        return new X509Extension("2.5.29.31", asnWriter.Encode(), critical: false);
    }

    private static X509Extension BuildAuthorityInformationAccessExtension(string? ocspUrl, string? caIssuersUrl)
    {
        // Authority Information Access Extension - OID 1.3.6.1.5.5.7.1.1
        // ASN.1 Structure:
        // AuthorityInfoAccessSyntax ::= SEQUENCE SIZE (1..MAX) OF AccessDescription
        // AccessDescription ::= SEQUENCE {
        //    accessMethod OBJECT IDENTIFIER,
        //    accessLocation GeneralName }
        // GeneralName ::= CHOICE {
        //    uniformResourceIdentifier [6] IA5String,
        //    ... }

        var asnWriter = new System.Formats.Asn1.AsnWriter(System.Formats.Asn1.AsnEncodingRules.DER);
        using (asnWriter.PushSequence()) // AuthorityInfoAccessSyntax SEQUENCE
        {
            // OCSP - id-ad-ocsp 1.3.6.1.5.5.7.48.1
            if (!string.IsNullOrEmpty(ocspUrl))
            {
                using (asnWriter.PushSequence()) // AccessDescription SEQUENCE
                {
                    asnWriter.WriteObjectIdentifier("1.3.6.1.5.5.7.48.1"); // id-ad-ocsp
                    asnWriter.WriteCharacterString(
                        System.Formats.Asn1.UniversalTagNumber.IA5String,
                        ocspUrl,
                        new System.Formats.Asn1.Asn1Tag(System.Formats.Asn1.TagClass.ContextSpecific, 6));
                }
            }

            // CA Issuers - id-ad-caIssuers 1.3.6.1.5.5.7.48.2
            if (!string.IsNullOrEmpty(caIssuersUrl))
            {
                using (asnWriter.PushSequence()) // AccessDescription SEQUENCE
                {
                    asnWriter.WriteObjectIdentifier("1.3.6.1.5.5.7.48.2"); // id-ad-caIssuers
                    asnWriter.WriteCharacterString(
                        System.Formats.Asn1.UniversalTagNumber.IA5String,
                        caIssuersUrl,
                        new System.Formats.Asn1.Asn1Tag(System.Formats.Asn1.TagClass.ContextSpecific, 6));
                }
            }
        }

        return new X509Extension("1.3.6.1.5.5.7.1.1", asnWriter.Encode(), critical: false);
    }
}
