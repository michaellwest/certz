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
            else if (days > 200)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"WARNING: Validity of {days} days exceeds the upcoming CA/Browser Forum limit.");
                Console.WriteLine("         After March 15, 2026, certificates must not exceed 200 days validity.");
                Console.WriteLine("         Your certificate will be non-compliant after this date.");
                Console.ResetColor();
            }
        });

        return daysOption;
    }

    internal static Option<StoreName> CreateStoreNameOption()
    {
        var storeNameOption = new Option<StoreName>("--storename", "--sn")
        {
            Description = "Specifies the store name.",
            DefaultValueFactory = _ => StoreName.My
        };
        return storeNameOption;
    }

    internal static Option<StoreLocation> CreateStoreLocationOption()
    {
        var storeLocationOption = new Option<StoreLocation>("--storelocation", "--sl")
        {
            Description = "Specifies the store location.",
            DefaultValueFactory = _ => StoreLocation.LocalMachine
        };
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
                return;
            }

            if (keySize == 2048)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("INFO: Using 2048-bit RSA key.");
                Console.WriteLine("      NIST recommends 3072+ bits for protection beyond 2030.");
                Console.WriteLine("      This key size is acceptable but consider --key-size 3072 or 4096.");
                Console.ResetColor();
            }
        });

        return keySizeOption;
    }

    internal static Option<string> CreateHashAlgorithmOption()
    {
        var hashAlgorithmOption = new Option<string>("--hash-algorithm", "--hash")
        {
            Description = "Hash algorithm (SHA256, SHA384, or SHA512). Default auto-selects based on key size.",
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

        return hashAlgorithmOption;
    }

    internal static readonly string[] validKeyTypes = ["RSA", "ECDSA-P256", "ECDSA-P384", "ECDSA-P521"];

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

            if (normalizedEncryption == "LEGACY")
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("INFO: Using legacy 3DES encryption for PFX.");
                Console.WriteLine("      This is for compatibility with older systems (Windows XP/Server 2003).");
                Console.WriteLine("      Consider using 'modern' (AES-256) for better security.");
                Console.ResetColor();
            }
        });

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
            Description = "Trust store location: CurrentUser (default, no admin required) or LocalMachine (requires admin, system-wide).",
            DefaultValueFactory = _ => StoreLocation.CurrentUser
        };
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
            Description = "Generate certificate in memory only (no files written to disk)",
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
            Description = "Stream certificate to stdout (no files written)"
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
}
