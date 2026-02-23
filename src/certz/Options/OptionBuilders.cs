using certz.Services;
using System.CommandLine.Completions;

namespace certz.Options;

internal static class OptionBuilders
{
    internal static Option<FileInfo?> CreateFileOption(bool isRequired, string[] aliases)
    {
        var allAliases = aliases ?? new[] { "--file", "--f" };
        var fileOption = new Option<FileInfo?>(allAliases[0], allAliases.Skip(1).ToArray())
        {
            Description = "Specifies the certificate.",
            Required = isRequired
        };

        return fileOption;
    }

    internal static Option<string?> CreateUrlOption(bool isRequired, string[] aliases)
    {
        var allAliases = aliases ?? new[] { "--url", "--u" };
        var urlOption = new Option<string?>(allAliases[0], allAliases.Skip(1).ToArray())
        {
            Description = "Specifies the remote URL to retrieve the certificate from.",
            Required = isRequired
        };

        return urlOption;
    }

    internal static Option<string> CreatePasswordOption()
    {
        var passwordOption = new Option<string>("--password", "--pass", "--p")
        {
            Description = "Password for the certificate."
        };

        return passwordOption;
    }

    internal static Option<FileInfo?> CreatePasswordFileOption()
    {
        var passwordFileOption = new Option<FileInfo?>("--password-file", "--pf")
        {
            Description = "File to write the generated password to. Only used when password is auto-generated.",
            Required = false
        };
        return passwordFileOption;
    }

    internal static Option<FileInfo?> CreatePasswordMapOption()
    {
        var option = new Option<FileInfo?>("--password-map", "--pm")
        {
            Description = "File mapping glob patterns to PFX passwords (format: pattern=password per line).",
            Required = false
        };
        return option;
    }

    internal static Option<int> CreateDaysOption(bool isRequired)
    {
        var daysOption = new Option<int>("--days")
        {
            Description = "Lifetime for the certificate (default: 90 days, max: 398 days current, 200 days after March 15, 2026).",
            DefaultValueFactory = _ => 90,
            Required = isRequired
        };

        daysOption.Validators.Add(result =>
        {
            var days = result.GetValueOrDefault<int>();
            var now = DateTime.UtcNow;

            // CA/Browser Forum Ballot SC-081v3 validity limits
            if (days < 1)
            {
                result.AddError("Certificate validity must be at least 1 day.");
                return;
            }

            if (days > 398)
            {
                result.AddError("Certificate validity exceeds current CA/Browser Forum limit (398 days). " +
                                     "Certificates will be rejected by browsers. " +
                                     "See: https://cabforum.org/working-groups/server/baseline-requirements/");
            }
            else if (now >= new DateTime(2026, 3, 15) && days > 200)
            {
                result.AddError("Certificate validity exceeds CA/Browser Forum limit effective March 15, 2026 (200 days). " +
                                     "See: https://cabforum.org/2025/04/11/ballot-sc081v3/");
            }
        });

        daysOption.CompletionSources.Add(new[] { "30", "90", "180", "365", "398" });

        return daysOption;
    }

    internal static Option<StoreName> CreateStoreNameOption()
    {
        var storeNameOption = new Option<StoreName>("--storename", "--sn")
        {
            Description = "Specifies the store name.",
            DefaultValueFactory = _ => StoreName.My
        };
        storeNameOption.CompletionSources.Add(new[]
        {
            "My", "Root", "CA", "TrustedPeople", "TrustedPublisher",
            "AuthRoot", "AddressBook", "Disallowed"
        });
        return storeNameOption;
    }

    internal static Option<StoreLocation> CreateStoreLocationOption()
    {
        var storeLocationOption = new Option<StoreLocation>("--storelocation", "--sl")
        {
            Description = "Specifies the store location.",
            DefaultValueFactory = _ => StoreLocation.LocalMachine
        };
        storeLocationOption.CompletionSources.Add(new[] { "LocalMachine", "CurrentUser" });
        return storeLocationOption;
    }

    internal static Option<string> CreateThumbprintOption()
    {
        var thumbprintOption = new Option<string>("--thumbprint", "--thumb")
        {
            Description = "The unique thumbprint for the certificate."
        };
        return thumbprintOption;
    }

    internal static Option<FileInfo?> CreateOutputCertOption()
    {
        var outputCertOption = new Option<FileInfo?>("--out-cert", "--oc")
        {
            Description = "Specifies the output certificate file (PEM format).",
            Required = false
        };
        return outputCertOption;
    }

    internal static Option<FileInfo?> CreateOutputKeyOption()
    {
        var outputKeyOption = new Option<FileInfo?>("--out-key", "--ok")
        {
            Description = "Specifies the output private key file (PEM format).",
            Required = false
        };
        return outputKeyOption;
    }

    internal static Option<int> CreateKeySizeOption()
    {
        var keySizeOption = new Option<int>("--key-size", "--ks")
        {
            Description = "RSA key size in bits (2048, 3072, or 4096). Default: 3072 (NIST recommended for protection beyond 2030).",
            DefaultValueFactory = _ => 3072
        };

        keySizeOption.Validators.Add(result =>
        {
            var keySize = result.GetValueOrDefault<int>();
            if (keySize != 2048 && keySize != 3072 && keySize != 4096)
            {
                result.AddError("Key size must be 2048, 3072, or 4096 bits.");
            }
        });

        // Only suggest key sizes when --key-type RSA has been typed
        keySizeOption.CompletionSources.Add((CompletionContext ctx) =>
        {
            var tokens = ctx.ParseResult.Tokens;
            for (int i = 0; i < tokens.Count - 1; i++)
            {
                if ((tokens[i].Value == "--key-type" || tokens[i].Value == "--kt") &&
                    tokens[i + 1].Value.Equals("RSA", StringComparison.OrdinalIgnoreCase))
                {
                    return new[] { "2048", "3072", "4096" };
                }
            }
            return Array.Empty<string>();
        });

        return keySizeOption;
    }

    internal static Option<string> CreateHashAlgorithmOption()
    {
        var hashAlgorithmOption = new Option<string>("--hash-algorithm", "--hash")
        {
            Description = "Hash algorithm for certificate signing. Default 'auto' selects based on key type and size: " +
                          "SHA-256 for ECDSA P-256 and RSA 2048; SHA-384 for ECDSA P-384 and RSA 3072; SHA-512 for ECDSA P-521 and RSA 4096.",
            DefaultValueFactory = _ => "auto"
        };

        hashAlgorithmOption.Validators.Add(result =>
        {
            var hashAlgorithm = result.GetValueOrDefault<string>();
            var hash = hashAlgorithm?.ToUpperInvariant();
            if (hash != "AUTO" && hash != "SHA256" && hash != "SHA384" && hash != "SHA512")
            {
                result.AddError("Hash algorithm must be auto, SHA256, SHA384, or SHA512.");
            }
        });

        hashAlgorithmOption.CompletionSources.Add(new[] { "auto", "SHA256", "SHA384", "SHA512" });

        return hashAlgorithmOption;
    }

    internal static readonly string[] validKeyTypes = ["RSA", "ECDSA-P256", "ECDSA-P384", "ECDSA-P521"];

    private static readonly string[] validEkuValues =
        ["serverAuth", "clientAuth", "codeSigning", "emailProtection"];

    private static readonly string[] iso3166Alpha2 =
    [
        "AD", "AE", "AF", "AG", "AI", "AL", "AM", "AO", "AQ", "AR", "AS", "AT", "AU", "AW", "AX", "AZ",
        "BA", "BB", "BD", "BE", "BF", "BG", "BH", "BI", "BJ", "BL", "BM", "BN", "BO", "BQ", "BR", "BS",
        "BT", "BV", "BW", "BY", "BZ", "CA", "CC", "CD", "CF", "CG", "CH", "CI", "CK", "CL", "CM", "CN",
        "CO", "CR", "CU", "CV", "CW", "CX", "CY", "CZ", "DE", "DJ", "DK", "DM", "DO", "DZ", "EC", "EE",
        "EG", "EH", "ER", "ES", "ET", "FI", "FJ", "FK", "FM", "FO", "FR", "GA", "GB", "GD", "GE", "GF",
        "GG", "GH", "GI", "GL", "GM", "GN", "GP", "GQ", "GR", "GS", "GT", "GU", "GW", "GY", "HK", "HM",
        "HN", "HR", "HT", "HU", "ID", "IE", "IL", "IM", "IN", "IO", "IQ", "IR", "IS", "IT", "JE", "JM",
        "JO", "JP", "KE", "KG", "KH", "KI", "KM", "KN", "KP", "KR", "KW", "KY", "KZ", "LA", "LB", "LC",
        "LI", "LK", "LR", "LS", "LT", "LU", "LV", "LY", "MA", "MC", "MD", "ME", "MF", "MG", "MH", "MK",
        "ML", "MM", "MN", "MO", "MP", "MQ", "MR", "MS", "MT", "MU", "MV", "MW", "MX", "MY", "MZ", "NA",
        "NC", "NE", "NF", "NG", "NI", "NL", "NO", "NP", "NR", "NU", "NZ", "OM", "PA", "PE", "PF", "PG",
        "PH", "PK", "PL", "PM", "PN", "PR", "PS", "PT", "PW", "PY", "QA", "RE", "RO", "RS", "RU", "RW",
        "SA", "SB", "SC", "SD", "SE", "SG", "SH", "SI", "SJ", "SK", "SL", "SM", "SN", "SO", "SR", "SS",
        "ST", "SV", "SX", "SY", "SZ", "TC", "TD", "TF", "TG", "TH", "TJ", "TK", "TL", "TM", "TN", "TO",
        "TR", "TT", "TV", "TW", "TZ", "UA", "UG", "UM", "US", "UY", "UZ", "VA", "VC", "VE", "VG", "VI",
        "VN", "VU", "WF", "WS", "YE", "YT", "ZA", "ZM", "ZW"
    ];

    internal static Option<string> CreateKeyTypeOption()
    {
        var keyTypeOption = new Option<string>("--key-type", "--kt")
        {
            Description = "Key type: RSA, ECDSA-P256 (default), ECDSA-P384, or ECDSA-P521.",
            DefaultValueFactory = _ => "ECDSA-P256"
        };

        keyTypeOption.Validators.Add(result =>
        {
            var keyType = result.GetValueOrDefault<string>();
            var normalizedType = keyType?.ToUpperInvariant();
            if (!validKeyTypes.Contains(normalizedType))
            {
                result.AddError($"Key type must be one of: {string.Join(", ", validKeyTypes)}");
            }
        });

        keyTypeOption.CompletionSources.Add(validKeyTypes);

        return keyTypeOption;
    }

    internal static Option<string> CreateRsaPaddingOption()
    {
        var rsaPaddingOption = new Option<string>("--rsa-padding", "--rp")
        {
            Description = "RSA signature padding mode: pkcs1 (wider compatibility) or pss (default, modern, recommended for new certificates).",
            DefaultValueFactory = _ => "pss"
        };

        rsaPaddingOption.Validators.Add(result =>
        {
            var padding = result.GetValueOrDefault<string>();
            var normalizedPadding = padding?.ToUpperInvariant();
            if (normalizedPadding != "PKCS1" && normalizedPadding != "PSS")
            {
                result.AddError("RSA padding must be 'pkcs1' or 'pss'.");
            }
        });

        // Only suggest padding modes when --key-type RSA has been typed
        rsaPaddingOption.CompletionSources.Add((CompletionContext ctx) =>
        {
            var tokens = ctx.ParseResult.Tokens;
            for (int i = 0; i < tokens.Count - 1; i++)
            {
                if ((tokens[i].Value == "--key-type" || tokens[i].Value == "--kt") &&
                    tokens[i + 1].Value.Equals("RSA", StringComparison.OrdinalIgnoreCase))
                {
                    return new[] { "pkcs1", "pss" };
                }
            }
            return Array.Empty<string>();
        });

        return rsaPaddingOption;
    }

    internal static Option<bool> CreateIsCAOption()
    {
        var isCAOption = new Option<bool>("--is-ca")
        {
            Description = "Generate a CA certificate (Certificate Authority) instead of end-entity certificate.",
            DefaultValueFactory = _ => false
        };
        return isCAOption;
    }

    internal static Option<int> CreatePathLengthOption()
    {
        var pathLengthOption = new Option<int>("--path-length")
        {
            Description = "Path length constraint for CA certificates (default: unlimited). Only used with --is-ca.",
            DefaultValueFactory = _ => -1
        };
        return pathLengthOption;
    }

    internal static Option<string?> CreateCrlUrlOption()
    {
        var crlUrlOption = new Option<string?>("--crl-url")
        {
            Description = "CRL Distribution Point URL (e.g., http://crl.example.com/ca.crl).",
            DefaultValueFactory = _ => null
        };
        return crlUrlOption;
    }

    internal static Option<string?> CreateOcspUrlOption()
    {
        var ocspUrlOption = new Option<string?>("--ocsp-url")
        {
            Description = "OCSP responder URL (e.g., http://ocsp.example.com).",
            DefaultValueFactory = _ => null
        };
        return ocspUrlOption;
    }

    internal static Option<string?> CreateCAIssuersUrlOption()
    {
        var caIssuersUrlOption = new Option<string?>("--ca-issuers-url")
        {
            Description = "CA Issuers URL (e.g., http://certs.example.com/ca.cer).",
            DefaultValueFactory = _ => null
        };
        return caIssuersUrlOption;
    }

    internal static Option<string?> CreateSubjectOOption()
    {
        var subjectOOption = new Option<string?>("--subject-o", "--o")
        {
            Description = "Subject Organization (O) field.",
            DefaultValueFactory = _ => null
        };
        return subjectOOption;
    }

    internal static Option<string?> CreateSubjectOUOption()
    {
        var subjectOUOption = new Option<string?>("--subject-ou", "--ou")
        {
            Description = "Subject Organizational Unit (OU) field.",
            DefaultValueFactory = _ => null
        };
        return subjectOUOption;
    }

    internal static Option<string?> CreateSubjectCOption()
    {
        var subjectCOption = new Option<string?>("--subject-c", "--c")
        {
            Description = "Subject Country (C) field (2-letter country code).",
            DefaultValueFactory = _ => null
        };

        subjectCOption.Validators.Add(result =>
        {
            var country = result.GetValueOrDefault<string?>();
            if (!string.IsNullOrEmpty(country) && country.Length != 2)
            {
                result.AddError("Country code must be exactly 2 letters (e.g., US, GB, DE).");
            }
        });

        subjectCOption.CompletionSources.Add(iso3166Alpha2);

        return subjectCOption;
    }

    internal static Option<string?> CreateSubjectSTOption()
    {
        var subjectSTOption = new Option<string?>("--subject-st", "--st")
        {
            Description = "Subject State/Province (ST) field.",
            DefaultValueFactory = _ => null
        };
        return subjectSTOption;
    }

    internal static Option<string?> CreateSubjectLOption()
    {
        var subjectLOption = new Option<string?>("--subject-l", "--l")
        {
            Description = "Subject Locality/City (L) field.",
            DefaultValueFactory = _ => null
        };
        return subjectLOption;
    }

    internal static Option<string> CreatePfxEncryptionOption()
    {
        var pfxEncryptionOption = new Option<string>("--pfx-encryption", "--pe")
        {
            Description = "PFX encryption mode: modern (AES-256, default) or legacy (3DES, for older systems).",
            DefaultValueFactory = _ => "modern"
        };

        pfxEncryptionOption.Validators.Add(result =>
        {
            var encryption = result.GetValueOrDefault<string>();
            var normalizedEncryption = encryption?.ToUpperInvariant();
            if (normalizedEncryption != "MODERN" && normalizedEncryption != "LEGACY")
            {
                result.AddError("PFX encryption must be 'modern' or 'legacy'.");
            }

        });

        pfxEncryptionOption.CompletionSources.Add(new[] { "modern", "legacy" });

        return pfxEncryptionOption;
    }

    internal static Option<bool> CreateExportableOption()
    {
        var exportableOption = new Option<bool>("--exportable", "--exp")
        {
            Description = "Allow private key to be exported after installation (default: true).",
            DefaultValueFactory = _ => true
        };
        return exportableOption;
    }

    internal static Option<string> CreateFormatOption()
    {
        var formatOption = new Option<string>("--format", "--fmt")
        {
            Description = "Output format: text (default) or json",
            DefaultValueFactory = _ => "text"
        };

        formatOption.Validators.Add(result =>
        {
            var format = result.GetValueOrDefault<string>();
            var normalizedFormat = format?.ToLowerInvariant();
            if (normalizedFormat != "text" && normalizedFormat != "json")
            {
                result.AddError("Output format must be 'text' or 'json'.");
            }
        });

        formatOption.CompletionSources.Add(new[] { "text", "json" });

        return formatOption;
    }

    internal static Option<bool> CreateTrustOption()
    {
        var trustOption = new Option<bool>("--trust", "-t")
        {
            Description = "Install certificate to Root trust store after creation (use --trust-location to specify CurrentUser or LocalMachine).",
            DefaultValueFactory = _ => false
        };
        return trustOption;
    }

    internal static Option<StoreLocation> CreateTrustLocationOption()
    {
        var trustLocationOption = new Option<StoreLocation>("--trust-location", "--tl")
        {
            Description = "Trust store location: LocalMachine (default when admin, system-wide) or CurrentUser (no admin required, but triggers UI dialog for Root store).",
            DefaultValueFactory = _ => (OperatingSystem.IsWindows() && TrustHandler.IsRunningAsAdmin())
                ? StoreLocation.LocalMachine
                : StoreLocation.CurrentUser
        };
        trustLocationOption.CompletionSources.Add(new[] { "LocalMachine", "CurrentUser" });
        return trustLocationOption;
    }

    internal static Option<bool> CreateGuidedOption()
    {
        var guidedOption = new Option<bool>("--guided", "-g")
        {
            Description = "Launch interactive wizard mode.",
            DefaultValueFactory = _ => false
        };
        return guidedOption;
    }

    internal static Option<bool> CreateVerboseOption()
    {
        var verboseOption = new Option<bool>("--verbose", "-v")
        {
            Description = "Enable diagnostic output to stderr (operation steps, exception details).",
            DefaultValueFactory = _ => false
        };
        return verboseOption;
    }

    internal static Option<FileInfo?> CreateIssuerCertOption()
    {
        var issuerCertOption = new Option<FileInfo?>("--issuer-cert")
        {
            Description = "Path to issuing CA certificate (PFX or PEM format)."
        };
        return issuerCertOption;
    }

    internal static Option<FileInfo?> CreateIssuerKeyOption()
    {
        var issuerKeyOption = new Option<FileInfo?>("--issuer-key")
        {
            Description = "Path to issuing CA private key (required for PEM issuer)."
        };
        return issuerKeyOption;
    }

    internal static Option<string?> CreateIssuerPasswordOption()
    {
        var issuerPasswordOption = new Option<string?>("--issuer-password")
        {
            Description = "Password for issuer PFX file."
        };
        return issuerPasswordOption;
    }

    internal static Option<string?> CreateNameOption()
    {
        var nameOption = new Option<string?>("--name")
        {
            Description = "CA certificate name (Common Name)."
        };
        return nameOption;
    }

    /// <summary>
    /// Creates the --ephemeral option for in-memory certificate generation.
    /// </summary>
    internal static Option<bool> CreateEphemeralOption()
    {
        return new Option<bool>("--ephemeral", "-e")
        {
            Description = "Create and validate the certificate in memory only; no output is produced. " +
                          "Use this to verify that a set of flags produces a valid certificate without any side effects.",
            DefaultValueFactory = _ => false
        };
    }

    /// <summary>
    /// Creates the --pipe option for streaming output to stdout.
    /// </summary>
    internal static Option<bool> CreatePipeOption()
    {
        return new Option<bool>("--pipe")
        {
            Description = "Stream the certificate to stdout so another process can consume it via pipe. " +
                          "Use --pipe-format to select the output format (default: pem) and --pipe-password for PFX output."
        };
    }

    /// <summary>
    /// Creates the --pipe-format option.
    /// </summary>
    internal static Option<string?> CreatePipeFormatOption()
    {
        var option = new Option<string?>("--pipe-format")
        {
            Description = "Pipe output format: pem (default), pfx, cert, key"
        };
        option.Validators.Add(result =>
        {
            var value = result.GetValueOrDefault<string?>();
            if (value != null && !new[] { "pem", "pfx", "cert", "key" }.Contains(value.ToLowerInvariant()))
            {
                result.AddError("--pipe-format must be one of: pem, pfx, cert, key");
            }
        });
        option.CompletionSources.Add(new[] { "pem", "pfx", "cert", "key" });
        return option;
    }

    /// <summary>
    /// Creates the --pipe-password option for PFX pipe output.
    /// </summary>
    internal static Option<string?> CreatePipePasswordOption()
    {
        return new Option<string?>("--pipe-password")
        {
            Description = "Password for PFX pipe output (required for --pipe-format pfx)"
        };
    }

    /// <summary>
    /// Creates the --dry-run option for previewing what a command would do.
    /// </summary>
    internal static Option<bool> CreateDryRunOption()
    {
        return new Option<bool>("--dry-run", "--dr")
        {
            Description = "Preview what the command would do without executing it. Exit 0 on valid options, 1 on invalid.",
            DefaultValueFactory = _ => false
        };
    }

    /// <summary>
    /// Creates the --examples option to show usage examples with help output.
    /// </summary>
    internal static Option<bool> CreateExamplesOption()
    {
        return new Option<bool>("--examples", "-x")
        {
            Description = "Show usage examples with help output",
            DefaultValueFactory = _ => false
        };
    }

    /// <summary>
    /// Creates the --eku option for specifying Extended Key Usage values.
    /// </summary>
    internal static Option<string[]> CreateEkuOption()
    {
        var option = new Option<string[]>("--eku")
        {
            Description = "Extended Key Usage (can be repeated). Values: serverAuth, clientAuth, codeSigning, emailProtection. Default: serverAuth.",
            AllowMultipleArgumentsPerToken = true
        };
        option.Validators.Add(result =>
        {
            var values = result.GetValueOrDefault<string[]>() ?? Array.Empty<string>();
            var valid = new[] { "serverAuth", "clientAuth", "codeSigning", "emailProtection" };
            foreach (var v in values)
            {
                if (!valid.Contains(v, StringComparer.OrdinalIgnoreCase))
                {
                    result.AddError($"Unknown EKU value '{v}'. Valid values: {string.Join(", ", valid)}");
                }
            }
        });
        option.CompletionSources.Add(validEkuValues);
        return option;
    }
}
