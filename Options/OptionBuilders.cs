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
            Description = "RSA key size in bits (2048, 3072, or 4096). NIST recommends 3072+ for protection beyond 2030.",
            DefaultValueFactory = _ => 2048
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
                Console.WriteLine("      Consider using --key-size 3072 or 4096 for long-lived certificates.");
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

    internal static Option<string> CreateKeyTypeOption()
    {
        var keyTypeOption = new Option<string>("--key-type", "--kt")
        {
            Description = "Key type: RSA (default), ECDSA-P256, ECDSA-P384, or ECDSA-P521.",
            DefaultValueFactory = _ => "RSA"
        };

        keyTypeOption.Validators.Add(result =>
        {
            var keyType = result.GetValueOrDefault<string>();
            var normalizedType = keyType?.ToUpperInvariant();
            var validTypes = new[] { "RSA", "ECDSA-P256", "ECDSA-P384", "ECDSA-P521" };
            if (!validTypes.Contains(normalizedType))
            {
                result.AddError($"Key type must be one of: {string.Join(", ", validTypes)}");
            }
        });

        return keyTypeOption;
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
}
