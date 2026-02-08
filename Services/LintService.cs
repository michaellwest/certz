using System.Net.Http;
using System.Text;
using System.Text.RegularExpressions;
using certz.Models;

namespace certz.Services;

/// <summary>
/// Service for linting certificates against industry standards.
/// Validates against CA/B Forum Baseline Requirements, Mozilla NSS Policy,
/// and development certificate best practices.
/// </summary>
internal static class LintService
{
    /// <summary>
    /// Lints a certificate from a file.
    /// </summary>
    public static LintResult LintFile(LintOptions options)
    {
        var cert = LoadCertificateFromFile(options.Source, options.Password);

        try
        {
            return PerformLint(cert, options);
        }
        finally
        {
            cert.Dispose();
        }
    }

    /// <summary>
    /// Lints a certificate from an HTTPS URL.
    /// </summary>
    public static async Task<LintResult> LintUrlAsync(LintOptions options)
    {
        var cert = await FetchCertificateFromUrl(options.Source);

        try
        {
            return PerformLint(cert, options);
        }
        finally
        {
            cert.Dispose();
        }
    }

    /// <summary>
    /// Lints a certificate from the certificate store.
    /// </summary>
    public static LintResult LintFromStore(LintOptions options)
    {
        var cert = LoadCertificateFromStore(options);

        try
        {
            return PerformLint(cert, options);
        }
        finally
        {
            cert.Dispose();
        }
    }

    private static LintResult PerformLint(X509Certificate2 cert, LintOptions options)
    {
        var findings = new List<LintFinding>();

        // Determine certificate type
        var basicConstraints = cert.Extensions["2.5.29.19"] as X509BasicConstraintsExtension;
        var isCa = basicConstraints?.CertificateAuthority ?? false;
        var isRoot = cert.Subject == cert.Issuer;

        // Apply policy checks based on selected policy set
        var policySet = options.PolicySet.ToLowerInvariant();

        if (policySet == "cabf" || policySet == "mozilla" || policySet == "all")
        {
            findings.AddRange(CheckCaBForumRules(cert, isCa, isRoot));
        }

        if (policySet == "mozilla" || policySet == "all")
        {
            findings.AddRange(CheckMozillaNssRules(cert, isCa, isRoot));
        }

        if (policySet == "dev" || policySet == "all")
        {
            findings.AddRange(CheckDevCertRules(cert, isCa));
        }

        // Filter by minimum severity
        findings = findings
            .Where(f => f.Severity >= options.MinSeverity)
            .OrderByDescending(f => f.Severity)
            .ThenBy(f => f.RuleId)
            .ToList();

        var hasErrors = findings.Any(f => f.Severity == LintSeverity.Error);

        return new LintResult
        {
            Subject = cert.Subject,
            Thumbprint = cert.Thumbprint,
            Passed = !hasErrors,
            Findings = findings,
            PolicySet = options.PolicySet,
            IsCa = isCa,
            IsRoot = isRoot,
            SourcePath = options.Source
        };
    }

    #region CA/B Forum Baseline Requirements

    private static List<LintFinding> CheckCaBForumRules(X509Certificate2 cert, bool isCa, bool isRoot)
    {
        var findings = new List<LintFinding>();

        // BR-001: Maximum validity 398 days for leaf certs
        if (!isCa)
        {
            var validityDays = (cert.NotAfter - cert.NotBefore).Days;
            if (validityDays > 398)
            {
                findings.Add(new LintFinding
                {
                    RuleId = "BR-001",
                    RuleName = "Maximum Validity Period",
                    Severity = LintSeverity.Error,
                    Message = "Leaf certificate validity exceeds 398 days (CA/B Forum limit)",
                    Policy = "CA/B Forum BR",
                    ActualValue = $"{validityDays} days",
                    ExpectedValue = "<= 398 days"
                });
            }
        }

        // BR-003: RSA minimum 2048 bits
        var rsa = cert.GetRSAPublicKey();
        if (rsa != null && rsa.KeySize < 2048)
        {
            findings.Add(new LintFinding
            {
                RuleId = "BR-003",
                RuleName = "RSA Key Size",
                Severity = LintSeverity.Error,
                Message = "RSA key size is below minimum 2048 bits",
                Policy = "CA/B Forum BR",
                ActualValue = $"{rsa.KeySize} bits",
                ExpectedValue = ">= 2048 bits"
            });
        }

        // BR-004: ECDSA minimum P-256
        var ecdsa = cert.GetECDsaPublicKey();
        if (ecdsa != null && ecdsa.KeySize < 256)
        {
            findings.Add(new LintFinding
            {
                RuleId = "BR-004",
                RuleName = "ECDSA Key Size",
                Severity = LintSeverity.Error,
                Message = "ECDSA key size is below minimum P-256",
                Policy = "CA/B Forum BR",
                ActualValue = $"{ecdsa.KeySize} bits",
                ExpectedValue = ">= 256 bits (P-256)"
            });
        }

        // BR-005: SHA-1 prohibited
        var sigAlg = cert.SignatureAlgorithm.FriendlyName ?? "";
        if (sigAlg.Contains("SHA1", StringComparison.OrdinalIgnoreCase) ||
            sigAlg.Contains("sha1", StringComparison.OrdinalIgnoreCase))
        {
            findings.Add(new LintFinding
            {
                RuleId = "BR-005",
                RuleName = "SHA-1 Signature Prohibited",
                Severity = LintSeverity.Error,
                Message = "SHA-1 signatures are prohibited for new certificates",
                Policy = "CA/B Forum BR",
                ActualValue = sigAlg,
                ExpectedValue = "SHA-256 or stronger"
            });
        }

        // BR-007: SAN required for TLS certificates
        var sanExtension = cert.Extensions["2.5.29.17"];
        if (sanExtension == null && !isCa)
        {
            findings.Add(new LintFinding
            {
                RuleId = "BR-007",
                RuleName = "Subject Alternative Name Required",
                Severity = LintSeverity.Error,
                Message = "Subject Alternative Name extension is required for TLS certificates",
                Policy = "CA/B Forum BR"
            });
        }

        // BR-008: CN must be in SAN if present
        if (sanExtension != null && !isCa)
        {
            var cn = ExtractCommonName(cert.Subject);
            if (!string.IsNullOrEmpty(cn))
            {
                var sans = GetSubjectAlternativeNames(cert);
                if (!sans.Contains(cn, StringComparer.OrdinalIgnoreCase))
                {
                    findings.Add(new LintFinding
                    {
                        RuleId = "BR-008",
                        RuleName = "CN Must Be In SAN",
                        Severity = LintSeverity.Warning,
                        Message = "Common Name (CN) should also appear in Subject Alternative Names",
                        Policy = "CA/B Forum BR",
                        ActualValue = $"CN={cn}",
                        ExpectedValue = "CN value in SAN list"
                    });
                }
            }
        }

        // BR-009: Basic Constraints required for CA
        if (isCa)
        {
            var bc = cert.Extensions["2.5.29.19"] as X509BasicConstraintsExtension;
            if (bc == null)
            {
                findings.Add(new LintFinding
                {
                    RuleId = "BR-009",
                    RuleName = "Basic Constraints Required for CA",
                    Severity = LintSeverity.Error,
                    Message = "CA certificates must have Basic Constraints extension with CA=true",
                    Policy = "CA/B Forum BR"
                });
            }
            else if (!bc.Critical)
            {
                findings.Add(new LintFinding
                {
                    RuleId = "BR-009",
                    RuleName = "Basic Constraints Must Be Critical",
                    Severity = LintSeverity.Warning,
                    Message = "Basic Constraints extension should be marked critical for CA certificates",
                    Policy = "CA/B Forum BR"
                });
            }
        }

        // BR-010: Key Usage required
        var keyUsage = cert.Extensions["2.5.29.15"] as X509KeyUsageExtension;
        if (keyUsage == null)
        {
            findings.Add(new LintFinding
            {
                RuleId = "BR-010",
                RuleName = "Key Usage Recommended",
                Severity = LintSeverity.Warning,
                Message = "Key Usage extension is recommended",
                Policy = "CA/B Forum BR"
            });
        }
        else if (isCa)
        {
            // CA must have keyCertSign
            if (!keyUsage.KeyUsages.HasFlag(X509KeyUsageFlags.KeyCertSign))
            {
                findings.Add(new LintFinding
                {
                    RuleId = "BR-010",
                    RuleName = "CA Key Usage",
                    Severity = LintSeverity.Error,
                    Message = "CA certificates must have keyCertSign key usage",
                    Policy = "CA/B Forum BR",
                    ActualValue = keyUsage.KeyUsages.ToString()
                });
            }
        }

        // BR-011: EKU recommended for leaf certificates
        var eku = cert.Extensions["2.5.29.37"] as X509EnhancedKeyUsageExtension;
        if (eku == null && !isCa)
        {
            findings.Add(new LintFinding
            {
                RuleId = "BR-011",
                RuleName = "Extended Key Usage Recommended",
                Severity = LintSeverity.Info,
                Message = "Extended Key Usage extension is recommended for leaf certificates",
                Policy = "CA/B Forum BR"
            });
        }

        // BR-012: AKI required for non-root
        if (!isRoot)
        {
            var aki = cert.Extensions["2.5.29.35"]; // Authority Key Identifier
            if (aki == null)
            {
                findings.Add(new LintFinding
                {
                    RuleId = "BR-012",
                    RuleName = "Authority Key Identifier Required",
                    Severity = LintSeverity.Warning,
                    Message = "Non-root certificates should have Authority Key Identifier extension",
                    Policy = "CA/B Forum BR"
                });
            }
        }

        // BR-013: SKI recommended
        var ski = cert.Extensions["2.5.29.14"]; // Subject Key Identifier
        if (ski == null)
        {
            findings.Add(new LintFinding
            {
                RuleId = "BR-013",
                RuleName = "Subject Key Identifier Recommended",
                Severity = LintSeverity.Info,
                Message = "Subject Key Identifier extension is recommended",
                Policy = "CA/B Forum BR"
            });
        }

        // BR-015: Country code must be 2 letters if present
        var country = ExtractSubjectField(cert.Subject, "C");
        if (!string.IsNullOrEmpty(country) && country.Length != 2)
        {
            findings.Add(new LintFinding
            {
                RuleId = "BR-015",
                RuleName = "Country Code Length",
                Severity = LintSeverity.Error,
                Message = "Country code (C) must be exactly 2 characters (ISO 3166-1 alpha-2)",
                Policy = "CA/B Forum BR",
                ActualValue = $"C={country} ({country.Length} chars)",
                ExpectedValue = "2-character country code"
            });
        }

        // BR-016: Organization requires Country
        var org = ExtractSubjectField(cert.Subject, "O");
        if (!string.IsNullOrEmpty(org) && string.IsNullOrEmpty(country))
        {
            findings.Add(new LintFinding
            {
                RuleId = "BR-016",
                RuleName = "Organization Requires Country",
                Severity = LintSeverity.Error,
                Message = "If Organization (O) is present, Country (C) must also be present",
                Policy = "CA/B Forum BR",
                ActualValue = $"O={org}, C=(missing)"
            });
        }

        // BR-017: Wildcard only in leftmost label
        if (!isCa)
        {
            var sans = GetSubjectAlternativeNames(cert);
            foreach (var san in sans.Where(s => s.Contains('*')))
            {
                // Check if wildcard is not in leftmost position
                var parts = san.Split('.');
                if (parts.Length > 0)
                {
                    var leftmost = parts[0];
                    var hasEmbeddedWildcard = parts.Skip(1).Any(p => p.Contains('*'));

                    if (hasEmbeddedWildcard)
                    {
                        findings.Add(new LintFinding
                        {
                            RuleId = "BR-017",
                            RuleName = "Wildcard Position",
                            Severity = LintSeverity.Error,
                            Message = "Wildcard (*) is only allowed in the leftmost label",
                            Policy = "CA/B Forum BR",
                            ActualValue = san
                        });
                    }
                }
            }
        }

        return findings;
    }

    #endregion

    #region Mozilla NSS Policy

    private static List<LintFinding> CheckMozillaNssRules(X509Certificate2 cert, bool isCa, bool isRoot)
    {
        var findings = new List<LintFinding>();
        var validityYears = (cert.NotAfter - cert.NotBefore).TotalDays / 365.25;

        // NSS-002: Root CA max 25 years recommended
        if (isCa && isRoot && validityYears > 25)
        {
            findings.Add(new LintFinding
            {
                RuleId = "NSS-002",
                RuleName = "Root CA Maximum Validity",
                Severity = LintSeverity.Warning,
                Message = "Root CA validity exceeds recommended 25 years",
                Policy = "Mozilla NSS",
                ActualValue = $"{validityYears:F1} years",
                ExpectedValue = "<= 25 years"
            });
        }

        // NSS-003: Intermediate CA max 10 years recommended
        if (isCa && !isRoot && validityYears > 10)
        {
            findings.Add(new LintFinding
            {
                RuleId = "NSS-003",
                RuleName = "Intermediate CA Maximum Validity",
                Severity = LintSeverity.Warning,
                Message = "Intermediate CA validity exceeds recommended 10 years",
                Policy = "Mozilla NSS",
                ActualValue = $"{validityYears:F1} years",
                ExpectedValue = "<= 10 years"
            });
        }

        // NSS-004: Name Constraints recommended for intermediates
        if (isCa && !isRoot)
        {
            var nameConstraints = cert.Extensions["2.5.29.30"]; // Name Constraints OID
            if (nameConstraints == null)
            {
                findings.Add(new LintFinding
                {
                    RuleId = "NSS-004",
                    RuleName = "Name Constraints Recommended",
                    Severity = LintSeverity.Info,
                    Message = "Name Constraints extension is recommended for intermediate CAs to limit scope",
                    Policy = "Mozilla NSS"
                });
            }
        }

        // NSS-005: CRL or OCSP distribution point for non-root CA
        if (isCa && !isRoot)
        {
            var cdp = cert.Extensions["2.5.29.31"]; // CRL Distribution Points
            var aia = cert.Extensions["1.3.6.1.5.5.7.1.1"]; // Authority Info Access

            if (cdp == null && aia == null)
            {
                findings.Add(new LintFinding
                {
                    RuleId = "NSS-005",
                    RuleName = "Revocation Information Required",
                    Severity = LintSeverity.Warning,
                    Message = "Intermediate CA should have CRL Distribution Points or Authority Info Access (OCSP)",
                    Policy = "Mozilla NSS"
                });
            }
        }

        return findings;
    }

    #endregion

    #region Development Certificate Checks

    private static List<LintFinding> CheckDevCertRules(X509Certificate2 cert, bool isCa)
    {
        var findings = new List<LintFinding>();

        if (isCa) return findings; // Dev rules mainly for leaf certs

        var validityDays = (cert.NotAfter - cert.NotBefore).Days;

        // DEV-001: Warn if > 398 days
        if (validityDays > 398)
        {
            findings.Add(new LintFinding
            {
                RuleId = "DEV-001",
                RuleName = "Development Certificate Long Validity",
                Severity = LintSeverity.Warning,
                Message = "Development certificate has unusually long validity period",
                Policy = "Development",
                ActualValue = $"{validityDays} days",
                ExpectedValue = "<= 398 days recommended"
            });
        }

        // DEV-003: Recommend localhost + 127.0.0.1
        var sans = GetSubjectAlternativeNames(cert);

        var hasLocalhost = sans.Any(s =>
            s.Equals("localhost", StringComparison.OrdinalIgnoreCase));
        var hasLoopback = sans.Any(s =>
            s == "127.0.0.1" || s == "::1");

        if (!hasLocalhost || !hasLoopback)
        {
            var missing = new List<string>();
            if (!hasLocalhost) missing.Add("localhost");
            if (!hasLoopback) missing.Add("127.0.0.1");

            findings.Add(new LintFinding
            {
                RuleId = "DEV-003",
                RuleName = "Local Development SANs",
                Severity = LintSeverity.Info,
                Message = $"Consider adding {string.Join(" and ", missing)} to SANs for local development",
                Policy = "Development",
                ActualValue = sans.Count > 0 ? string.Join(", ", sans.Take(5)) : "(none)"
            });
        }

        return findings;
    }

    #endregion

    #region Certificate Loading

    private static X509Certificate2 LoadCertificateFromFile(string path, string? password)
    {
        if (!File.Exists(path))
        {
            throw new FileNotFoundException($"Certificate file not found: {path}");
        }

        var extension = Path.GetExtension(path).ToLowerInvariant();

        return extension switch
        {
            ".pfx" or ".p12" => LoadPfx(path, password),
            ".pem" => LoadPem(path),
            ".crt" or ".cer" => LoadCertFile(path),
            ".der" => LoadDer(path),
            _ => AutoDetectAndLoad(path, password)
        };
    }

    private static X509Certificate2 LoadPfx(string path, string? password)
    {
        var pfxData = File.ReadAllBytes(path);
        return X509CertificateLoader.LoadPkcs12(pfxData, password, X509KeyStorageFlags.Exportable);
    }

    private static X509Certificate2 LoadPem(string path)
    {
        var pemContent = File.ReadAllText(path);
        var certMatch = Regex.Match(pemContent, @"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", RegexOptions.Singleline);

        if (!certMatch.Success)
        {
            throw new InvalidOperationException("No certificate found in PEM file.");
        }

        if (pemContent.Contains("-----BEGIN PRIVATE KEY-----") ||
            pemContent.Contains("-----BEGIN RSA PRIVATE KEY-----") ||
            pemContent.Contains("-----BEGIN EC PRIVATE KEY-----"))
        {
            return X509Certificate2.CreateFromPem(certMatch.Value, pemContent);
        }

        return X509Certificate2.CreateFromPem(certMatch.Value);
    }

    private static X509Certificate2 LoadCertFile(string path)
    {
        var data = File.ReadAllBytes(path);
        var text = Encoding.UTF8.GetString(data);

        if (text.Contains("-----BEGIN CERTIFICATE-----"))
        {
            return LoadPem(path);
        }

        return X509CertificateLoader.LoadCertificate(data);
    }

    private static X509Certificate2 LoadDer(string path)
    {
        var data = File.ReadAllBytes(path);
        return X509CertificateLoader.LoadCertificate(data);
    }

    private static X509Certificate2 AutoDetectAndLoad(string path, string? password)
    {
        var data = File.ReadAllBytes(path);
        var text = Encoding.UTF8.GetString(data);

        if (text.Contains("-----BEGIN"))
        {
            return LoadPem(path);
        }

        try
        {
            return LoadPfx(path, password);
        }
        catch
        {
            // Not a PFX
        }

        try
        {
            return X509CertificateLoader.LoadCertificate(data);
        }
        catch
        {
            throw new InvalidOperationException($"Unable to determine certificate format for: {path}");
        }
    }

    private static async Task<X509Certificate2> FetchCertificateFromUrl(string url)
    {
        X509Certificate2? certificate = null;

        var handler = new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = (message, cert, chain, errors) =>
            {
                if (cert != null)
                {
                    certificate = X509CertificateLoader.LoadCertificate(cert.GetRawCertData());
                }
                return true;
            }
        };

        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30) };

        try
        {
            await client.GetAsync(url);
        }
        catch (HttpRequestException) { }
        catch (TaskCanceledException) { }

        if (certificate == null)
        {
            throw new InvalidOperationException($"Could not retrieve certificate from {url}");
        }

        return certificate;
    }

    private static X509Certificate2 LoadCertificateFromStore(LintOptions options)
    {
        var location = options.StoreLocation?.ToLowerInvariant() switch
        {
            "localmachine" => StoreLocation.LocalMachine,
            _ => StoreLocation.CurrentUser
        };

        var name = options.StoreName?.ToLowerInvariant() switch
        {
            "root" => StoreName.Root,
            "ca" => StoreName.CertificateAuthority,
            "my" or null => StoreName.My,
            _ => StoreName.My
        };

        using var store = new X509Store(name, location);
        store.Open(OpenFlags.ReadOnly);

        var thumbprint = options.Source.Replace(" ", "").ToUpperInvariant();
        var cert = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false)
            .OfType<X509Certificate2>()
            .FirstOrDefault();

        if (cert == null)
        {
            throw new InvalidOperationException($"Certificate with thumbprint {thumbprint} not found in {location}\\{name}");
        }

        // Clone the certificate to avoid issues after store is closed
        return X509CertificateLoader.LoadCertificate(cert.RawData);
    }

    #endregion

    #region Helper Methods

    private static List<string> GetSubjectAlternativeNames(X509Certificate2 cert)
    {
        var sans = new List<string>();
        var sanExtension = cert.Extensions["2.5.29.17"];

        if (sanExtension == null) return sans;

        var asnData = new AsnEncodedData(sanExtension.Oid!, sanExtension.RawData);
        var formatted = asnData.Format(true);

        foreach (var line in formatted.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
        {
            var trimmed = line.Trim();
            if (trimmed.StartsWith("DNS Name=", StringComparison.OrdinalIgnoreCase))
            {
                sans.Add(trimmed.Substring("DNS Name=".Length));
            }
            else if (trimmed.StartsWith("IP Address=", StringComparison.OrdinalIgnoreCase))
            {
                sans.Add(trimmed.Substring("IP Address=".Length));
            }
        }

        return sans;
    }

    private static string? ExtractCommonName(string subject)
    {
        return ExtractSubjectField(subject, "CN");
    }

    private static string? ExtractSubjectField(string subject, string field)
    {
        // Parse DN to extract field value
        // Format: "CN=name, O=org, C=US" or similar
        var pattern = $@"(?:^|,\s*){field}=([^,]+)";
        var match = Regex.Match(subject, pattern, RegexOptions.IgnoreCase);
        return match.Success ? match.Groups[1].Value.Trim() : null;
    }

    #endregion
}
