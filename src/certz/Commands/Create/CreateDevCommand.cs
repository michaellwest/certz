using certz.Formatters;
using certz.Models;
using certz.Options;
using certz.Services;

namespace certz.Commands.Create;

internal static class CreateDevCommand
{
    internal static Command BuildCreateDevCommand()
    {
        // Domain argument (optional if --guided)
        var domainArgument = new Argument<string?>("domain")
        {
            Description = "Primary domain name for the certificate",
            Arity = ArgumentArity.ZeroOrOne
        };

        // Options
        var guidedOption = OptionBuilders.CreateGuidedOption();
        var trustOption = OptionBuilders.CreateTrustOption();
        var trustLocationOption = OptionBuilders.CreateTrustLocationOption();
        var issuerCertOption = OptionBuilders.CreateIssuerCertOption();
        var issuerKeyOption = OptionBuilders.CreateIssuerKeyOption();
        var issuerPasswordOption = OptionBuilders.CreateIssuerPasswordOption();

        var sanOption = new Option<string[]>("--san")
        {
            Description = "Additional Subject Alternative Names (can be repeated)",
            AllowMultipleArgumentsPerToken = true
        };

        var daysOption = OptionBuilders.CreateDaysOption(false);
        var keyTypeOption = OptionBuilders.CreateKeyTypeOption();
        var keySizeOption = OptionBuilders.CreateKeySizeOption();
        var hashAlgorithmOption = OptionBuilders.CreateHashAlgorithmOption();
        var rsaPaddingOption = OptionBuilders.CreateRsaPaddingOption();
        var pfxEncryptionOption = OptionBuilders.CreatePfxEncryptionOption();

        var pfxOption = OptionBuilders.CreateFileOption(false, new[] { "--file", "--f", "--pkcs12" });
        var certOption = OptionBuilders.CreateFileOption(false, new[] { "--cert", "--c" });
        var keyOption = OptionBuilders.CreateFileOption(false, new[] { "--key", "--k" });
        var passwordOption = OptionBuilders.CreatePasswordOption();
        var passwordFileOption = OptionBuilders.CreatePasswordFileOption();
        var formatOption = OptionBuilders.CreateFormatOption();

        // EKU option
        var ekuOption = OptionBuilders.CreateEkuOption();

        // Ephemeral and pipe options
        var ephemeralOption = OptionBuilders.CreateEphemeralOption();
        var pipeOption = OptionBuilders.CreatePipeOption();
        var pipeFormatOption = OptionBuilders.CreatePipeFormatOption();
        var pipePasswordOption = OptionBuilders.CreatePipePasswordOption();

        var dryRunOption = OptionBuilders.CreateDryRunOption();

        var command = new Command("dev", "Create a development/server certificate")
        {
            domainArgument,
            guidedOption,
            trustOption,
            trustLocationOption,
            issuerCertOption,
            issuerKeyOption,
            issuerPasswordOption,
            sanOption,
            daysOption,
            keyTypeOption,
            keySizeOption,
            hashAlgorithmOption,
            rsaPaddingOption,
            pfxEncryptionOption,
            pfxOption,
            certOption,
            keyOption,
            passwordOption,
            passwordFileOption,
            formatOption,
            ephemeralOption,
            pipeOption,
            pipeFormatOption,
            pipePasswordOption,
            ekuOption,
            dryRunOption
        };

        command.SetAction(async (parseResult) =>
        {
            var guided = parseResult.GetValue(guidedOption);
            var format = parseResult.GetValue(formatOption) ?? "text";
            var formatter = FormatterFactory.Create(format);
            var dryRun = parseResult.GetValue(dryRunOption);

            // Get ephemeral and pipe options
            var ephemeral = parseResult.GetValue(ephemeralOption);
            var pipe = parseResult.GetValue(pipeOption);
            var pipeFormat = parseResult.GetValue(pipeFormatOption);
            var pipePassword = parseResult.GetValue(pipePasswordOption);

            // Get file options for validation
            var pfxFile = parseResult.GetValue(pfxOption);
            var certFile = parseResult.GetValue(certOption);
            var keyFile = parseResult.GetValue(keyOption);
            var trust = parseResult.GetValue(trustOption);
            var passwordFile = parseResult.GetValue(passwordFileOption);

            // Validate mutual exclusivity
            if (ephemeral || pipe)
            {
                if (pfxFile != null || certFile != null || keyFile != null)
                {
                    throw new ArgumentException("--ephemeral and --pipe cannot be used with file output options (--file, --cert, --key).");
                }
                if (trust)
                {
                    throw new ArgumentException("--ephemeral and --pipe cannot be used with --trust.");
                }
                if (passwordFile != null)
                {
                    throw new ArgumentException("--ephemeral and --pipe cannot be used with --password-file.");
                }
            }

            if (ephemeral && pipe)
            {
                throw new ArgumentException("--ephemeral and --pipe are mutually exclusive. Use one or the other.");
            }

            // Validate pipe-format requires pipe
            if (pipeFormat != null && !pipe)
            {
                throw new ArgumentException("--pipe-format requires --pipe flag.");
            }

            // Validate pipe-password requires pipe
            if (pipePassword != null && !pipe)
            {
                throw new ArgumentException("--pipe-password requires --pipe flag.");
            }

            DevCertificateOptions options;

            if (guided)
            {
                try
                {
                    options = CertificateWizard.RunDevCertificateWizard();
                }
                catch (OperationCanceledException)
                {
                    return;
                }
            }
            else
            {
                var domain = parseResult.GetValue(domainArgument);
                if (string.IsNullOrWhiteSpace(domain))
                {
                    formatter.WriteError("Domain name is required. Use 'certz create dev <domain>' or 'certz create dev --guided'.");
                    return;
                }

                options = new DevCertificateOptions
                {
                    Domain = domain,
                    AdditionalSANs = parseResult.GetValue(sanOption) ?? Array.Empty<string>(),
                    Days = parseResult.GetValue(daysOption),
                    KeyType = parseResult.GetValue(keyTypeOption) ?? "ECDSA-P256",
                    KeySize = parseResult.GetValue(keySizeOption),
                    HashAlgorithm = parseResult.GetValue(hashAlgorithmOption) ?? "auto",
                    RsaPadding = parseResult.GetValue(rsaPaddingOption) ?? "pss",
                    PfxEncryption = parseResult.GetValue(pfxEncryptionOption) ?? "modern",
                    Trust = trust,
                    TrustLocation = parseResult.GetValue(trustLocationOption),
                    IssuerCert = parseResult.GetValue(issuerCertOption),
                    IssuerKey = parseResult.GetValue(issuerKeyOption),
                    IssuerPassword = parseResult.GetValue(issuerPasswordOption),
                    PfxFile = pfxFile,
                    CertFile = certFile,
                    KeyFile = keyFile,
                    Password = parseResult.GetValue(passwordOption),
                    PasswordFile = passwordFile,
                    Ephemeral = ephemeral,
                    Pipe = pipe,
                    PipeFormat = pipeFormat,
                    PipePassword = pipePassword,
                    Eku = parseResult.GetValue(ekuOption) ?? Array.Empty<string>()
                };
            }

            // If no output files specified and not ephemeral/pipe, default to PFX
            if (!options.Ephemeral && !options.Pipe &&
                options.PfxFile == null && options.CertFile == null && options.KeyFile == null)
            {
                options = options with { PfxFile = new FileInfo($"{options.Domain.Replace("*", "wildcard").Replace(".", "-")}.pfx") };
            }

            // Dry-run: show preview without executing
            if (dryRun)
            {
                var allSANs = new List<string> { options.Domain };
                allSANs.AddRange(options.AdditionalSANs);

                var hash = ResolveHashAlgorithm(options.KeyType, options.KeySize, options.HashAlgorithm);
                var utcToday = DateTimeOffset.UtcNow.Date;
                var validFrom = utcToday.ToString("yyyy-MM-dd");
                var validTo = utcToday.AddDays(options.Days).AddDays(-1).ToString("yyyy-MM-dd");

                var keyDesc = options.KeyType.ToUpperInvariant().StartsWith("ECDSA")
                    ? options.KeyType
                    : $"RSA {options.KeySize}-bit";

                string outputDesc;
                if (options.Ephemeral) outputDesc = "(ephemeral, no file)";
                else if (options.Pipe) outputDesc = $"(pipe, format: {options.PipeFormat ?? "pem"})";
                else outputDesc = options.PfxFile?.Name ?? options.CertFile?.Name ?? options.KeyFile?.Name ?? "(auto)";

                var ekuDisplay = options.Eku.Length > 0
                    ? string.Join(", ", options.Eku)
                    : "serverAuth";

                var trustDesc = options.Trust
                    ? $"yes ({options.TrustLocation}/Root)"
                    : "no";

                var details = new List<DryRunDetail>
                {
                    new("Subject",   $"CN={options.Domain}"),
                    new("SANs",      string.Join(", ", allSANs)),
                    new("Key Type",  keyDesc),
                    new("Hash",      hash),
                    new("Valid From", $"{validFrom} UTC"),
                    new("Valid To",   $"{validTo} UTC"),
                    new("Days",       options.Days.ToString()),
                    new("EKU",        ekuDisplay),
                    new("Trust",      trustDesc),
                    new("Output",     outputDesc)
                };

                if (options.IssuerCert != null)
                    details.Add(new("Signed By", options.IssuerCert.Name));

                formatter.WriteDryRunResult(new DryRunResult
                {
                    Command = "create dev",
                    Action = $"Create development certificate for {options.Domain}",
                    Details = details.ToArray()
                });
                return;
            }

            var result = await CreateService.CreateDevCertificate(options);
            formatter.WriteCertificateCreated(result);

            if (guided)
                CertificateWizard.WriteEquivalentCommand(CertificateWizard.BuildDevCommandLine(options));
        });

        return command;
    }

    private static string ResolveHashAlgorithm(string keyType, int keySize, string hashAlgorithm)
    {
        if (!hashAlgorithm.Equals("auto", StringComparison.OrdinalIgnoreCase))
        {
            return hashAlgorithm.ToUpperInvariant() switch
            {
                "SHA256" => "SHA-256",
                "SHA384" => "SHA-384",
                "SHA512" => "SHA-512",
                _ => hashAlgorithm
            };
        }

        var kt = keyType.ToUpperInvariant();
        if (kt.Contains("P521")) return "SHA-512";
        if (kt.Contains("P384")) return "SHA-384";
        if (kt.Contains("ECDSA")) return "SHA-256";
        // RSA
        if (keySize >= 4096) return "SHA-512";
        if (keySize >= 3072) return "SHA-384";
        return "SHA-256";
    }
}
