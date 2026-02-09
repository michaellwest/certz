using certz.Formatters;
using certz.Models;
using certz.Options;
using certz.Services;

namespace certz.Commands.Create;

internal static class CreateCaCommand
{
    internal static Command BuildCreateCaCommand()
    {
        // Options
        var nameOption = OptionBuilders.CreateNameOption();
        var guidedOption = OptionBuilders.CreateGuidedOption();
        var trustOption = OptionBuilders.CreateTrustOption();
        var trustLocationOption = OptionBuilders.CreateTrustLocationOption();
        var pathLengthOption = OptionBuilders.CreatePathLengthOption();

        var daysOption = new Option<int>("--days")
        {
            Description = "Certificate validity in days (default: 3650, ~10 years)",
            DefaultValueFactory = _ => 3650
        };

        var keyTypeOption = OptionBuilders.CreateKeyTypeOption();
        var keySizeOption = OptionBuilders.CreateKeySizeOption();
        var hashAlgorithmOption = OptionBuilders.CreateHashAlgorithmOption();
        var rsaPaddingOption = OptionBuilders.CreateRsaPaddingOption();
        var pfxEncryptionOption = OptionBuilders.CreatePfxEncryptionOption();

        var crlUrlOption = OptionBuilders.CreateCrlUrlOption();
        var ocspUrlOption = OptionBuilders.CreateOcspUrlOption();
        var caIssuersUrlOption = OptionBuilders.CreateCAIssuersUrlOption();

        var pfxOption = OptionBuilders.CreateFileOption(false, new[] { "--file", "--f", "--pkcs12" });
        var certOption = OptionBuilders.CreateFileOption(false, new[] { "--cert", "--c" });
        var keyOption = OptionBuilders.CreateFileOption(false, new[] { "--key", "--k" });
        var passwordOption = OptionBuilders.CreatePasswordOption();
        var passwordFileOption = OptionBuilders.CreatePasswordFileOption();
        var formatOption = OptionBuilders.CreateFormatOption();

        // Ephemeral and pipe options
        var ephemeralOption = OptionBuilders.CreateEphemeralOption();
        var pipeOption = OptionBuilders.CreatePipeOption();
        var pipeFormatOption = OptionBuilders.CreatePipeFormatOption();
        var pipePasswordOption = OptionBuilders.CreatePipePasswordOption();

        var command = new Command("ca", "Create a Certificate Authority (CA) certificate")
        {
            nameOption,
            guidedOption,
            trustOption,
            trustLocationOption,
            pathLengthOption,
            daysOption,
            keyTypeOption,
            keySizeOption,
            hashAlgorithmOption,
            rsaPaddingOption,
            pfxEncryptionOption,
            crlUrlOption,
            ocspUrlOption,
            caIssuersUrlOption,
            pfxOption,
            certOption,
            keyOption,
            passwordOption,
            passwordFileOption,
            formatOption,
            ephemeralOption,
            pipeOption,
            pipeFormatOption,
            pipePasswordOption
        };

        command.SetAction(async (parseResult) =>
        {
            var guided = parseResult.GetValue(guidedOption);
            var format = parseResult.GetValue(formatOption) ?? "text";
            var formatter = FormatterFactory.Create(format);

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
                    formatter.WriteError("--ephemeral and --pipe cannot be used with file output options (--file, --cert, --key).");
                    return;
                }
                if (trust)
                {
                    formatter.WriteError("--ephemeral and --pipe cannot be used with --trust.");
                    return;
                }
                if (passwordFile != null)
                {
                    formatter.WriteError("--ephemeral and --pipe cannot be used with --password-file.");
                    return;
                }
            }

            if (ephemeral && pipe)
            {
                formatter.WriteError("--ephemeral and --pipe are mutually exclusive. Use one or the other.");
                return;
            }

            // Validate pipe-format requires pipe
            if (pipeFormat != null && !pipe)
            {
                formatter.WriteError("--pipe-format requires --pipe flag.");
                return;
            }

            // Validate pipe-password requires pipe
            if (pipePassword != null && !pipe)
            {
                formatter.WriteError("--pipe-password requires --pipe flag.");
                return;
            }

            CACertificateOptions options;

            if (guided)
            {
                try
                {
                    options = CertificateWizard.RunCACertificateWizard();
                }
                catch (OperationCanceledException)
                {
                    return;
                }
            }
            else
            {
                var name = parseResult.GetValue(nameOption);
                if (string.IsNullOrWhiteSpace(name))
                {
                    formatter.WriteError("CA name is required. Use 'certz create ca --name <name>' or 'certz create ca --guided'.");
                    return;
                }

                options = new CACertificateOptions
                {
                    Name = name,
                    Days = parseResult.GetValue(daysOption),
                    PathLength = parseResult.GetValue(pathLengthOption),
                    KeyType = parseResult.GetValue(keyTypeOption) ?? "ECDSA-P256",
                    KeySize = parseResult.GetValue(keySizeOption),
                    HashAlgorithm = parseResult.GetValue(hashAlgorithmOption) ?? "auto",
                    RsaPadding = parseResult.GetValue(rsaPaddingOption) ?? "pss",
                    PfxEncryption = parseResult.GetValue(pfxEncryptionOption) ?? "modern",
                    Trust = trust,
                    TrustLocation = parseResult.GetValue(trustLocationOption),
                    CrlUrl = parseResult.GetValue(crlUrlOption),
                    OcspUrl = parseResult.GetValue(ocspUrlOption),
                    CAIssuersUrl = parseResult.GetValue(caIssuersUrlOption),
                    PfxFile = pfxFile,
                    CertFile = certFile,
                    KeyFile = keyFile,
                    Password = parseResult.GetValue(passwordOption),
                    PasswordFile = passwordFile,
                    Ephemeral = ephemeral,
                    Pipe = pipe,
                    PipeFormat = pipeFormat,
                    PipePassword = pipePassword
                };
            }

            // If no output files specified and not ephemeral/pipe, default to PFX
            if (!options.Ephemeral && !options.Pipe &&
                options.PfxFile == null && options.CertFile == null && options.KeyFile == null)
            {
                options = options with { PfxFile = new FileInfo($"{options.Name.Replace(" ", "-").ToLowerInvariant()}.pfx") };
            }

            var result = await CreateService.CreateCACertificate(options);
            formatter.WriteCertificateCreated(result);
        });

        return command;
    }
}
