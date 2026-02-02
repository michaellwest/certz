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
            formatOption
        };

        command.SetAction(async (parseResult) =>
        {
            var guided = parseResult.GetValue(guidedOption);
            var format = parseResult.GetValue(formatOption) ?? "text";
            var formatter = FormatterFactory.Create(format);

            CACertificateOptions options;

            if (guided)
            {
                options = CertificateWizard.RunCACertificateWizard();
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
                    Trust = parseResult.GetValue(trustOption),
                    TrustLocation = parseResult.GetValue(trustLocationOption),
                    CrlUrl = parseResult.GetValue(crlUrlOption),
                    OcspUrl = parseResult.GetValue(ocspUrlOption),
                    CAIssuersUrl = parseResult.GetValue(caIssuersUrlOption),
                    PfxFile = parseResult.GetValue(pfxOption),
                    CertFile = parseResult.GetValue(certOption),
                    KeyFile = parseResult.GetValue(keyOption),
                    Password = parseResult.GetValue(passwordOption),
                    PasswordFile = parseResult.GetValue(passwordFileOption)
                };
            }

            // If no output files specified, default to PFX
            if (options.PfxFile == null && options.CertFile == null && options.KeyFile == null)
            {
                options = options with { PfxFile = new FileInfo($"{options.Name.Replace(" ", "-").ToLowerInvariant()}.pfx") };
            }

            var result = await CertificateOperationsV2.CreateCACertificate(options);
            formatter.WriteCertificateCreated(result);
        });

        return command;
    }
}
