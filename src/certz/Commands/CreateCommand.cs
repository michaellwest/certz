using certz.Commands.Create;
using certz.Formatters;
using certz.Models;
using certz.Options;
using certz.Services;

namespace certz.Commands;

internal static class CreateCommand
{
    internal static void AddCreateCommand(this RootCommand rootCommand)
    {
        var createCommand = new Command("create", "Certificate creation commands");

        // Add subcommands
        createCommand.Subcommands.Add(CreateDevCommand.BuildCreateDevCommand());
        createCommand.Subcommands.Add(CreateCaCommand.BuildCreateCaCommand());

        // Legacy behavior: when 'create' is called directly with options, use the old behavior
        AddLegacyCreateOptions(createCommand);

        rootCommand.Add(createCommand);
    }

    private static void AddLegacyCreateOptions(Command createCommand)
    {
        var pfxOption = OptionBuilders.CreateFileOption(false, new[] { "--file", "--f", "--pkcs12" });
        var certOption = OptionBuilders.CreateFileOption(false, new[] { "--cert", "--c" });
        var keyOption = OptionBuilders.CreateFileOption(false, new[] { "--key", "--k" });
        var passwordOption = OptionBuilders.CreatePasswordOption();
        var passwordFileOption = OptionBuilders.CreatePasswordFileOption();
        var dnsOption = new Option<string[]>("--dns", "--san")
        {
            Description = "SAN for the certificate.",
            DefaultValueFactory = _ => new[] { "*.dev.local", "*.localhost", "*.test" },
            AllowMultipleArgumentsPerToken = true
        };
        var daysOption = OptionBuilders.CreateDaysOption(false);
        var keySizeOption = OptionBuilders.CreateKeySizeOption();
        var hashAlgorithmOption = OptionBuilders.CreateHashAlgorithmOption();
        var keyTypeOption = OptionBuilders.CreateKeyTypeOption();
        var rsaPaddingOption = OptionBuilders.CreateRsaPaddingOption();
        var pfxEncryptionOption = OptionBuilders.CreatePfxEncryptionOption();
        var isCAOption = OptionBuilders.CreateIsCAOption();
        var pathLengthOption = OptionBuilders.CreatePathLengthOption();
        var crlUrlOption = OptionBuilders.CreateCrlUrlOption();
        var ocspUrlOption = OptionBuilders.CreateOcspUrlOption();
        var caIssuersUrlOption = OptionBuilders.CreateCAIssuersUrlOption();
        var subjectOOption = OptionBuilders.CreateSubjectOOption();
        var subjectOUOption = OptionBuilders.CreateSubjectOUOption();
        var subjectCOption = OptionBuilders.CreateSubjectCOption();
        var subjectSTOption = OptionBuilders.CreateSubjectSTOption();
        var subjectLOption = OptionBuilders.CreateSubjectLOption();
        var formatOption = OptionBuilders.CreateFormatOption();

        createCommand.Options.Add(pfxOption);
        createCommand.Options.Add(passwordOption);
        createCommand.Options.Add(passwordFileOption);
        createCommand.Options.Add(certOption);
        createCommand.Options.Add(keyOption);
        createCommand.Options.Add(dnsOption);
        createCommand.Options.Add(daysOption);
        createCommand.Options.Add(keySizeOption);
        createCommand.Options.Add(hashAlgorithmOption);
        createCommand.Options.Add(keyTypeOption);
        createCommand.Options.Add(rsaPaddingOption);
        createCommand.Options.Add(pfxEncryptionOption);
        createCommand.Options.Add(isCAOption);
        createCommand.Options.Add(pathLengthOption);
        createCommand.Options.Add(crlUrlOption);
        createCommand.Options.Add(ocspUrlOption);
        createCommand.Options.Add(caIssuersUrlOption);
        createCommand.Options.Add(subjectOOption);
        createCommand.Options.Add(subjectOUOption);
        createCommand.Options.Add(subjectCOption);
        createCommand.Options.Add(subjectSTOption);
        createCommand.Options.Add(subjectLOption);
        createCommand.Options.Add(formatOption);

        createCommand.SetAction(async (parseResult) =>
        {
            var pfx = parseResult.GetValue(pfxOption);
            var password = parseResult.GetValue(passwordOption);
            var passwordFile = parseResult.GetValue(passwordFileOption);
            var cert = parseResult.GetValue(certOption);
            var key = parseResult.GetValue(keyOption);
            var dnsNames = parseResult.GetValue(dnsOption) ?? Array.Empty<string>();
            var days = parseResult.GetValue(daysOption);
            var keySize = parseResult.GetValue(keySizeOption);
            var hashAlgorithm = parseResult.GetValue(hashAlgorithmOption) ?? "auto";
            var keyType = parseResult.GetValue(keyTypeOption) ?? "ECDSA-P256";
            var rsaPadding = parseResult.GetValue(rsaPaddingOption) ?? "pss";
            var pfxEncryption = parseResult.GetValue(pfxEncryptionOption) ?? "modern";
            var isCA = parseResult.GetValue(isCAOption);
            var pathLength = parseResult.GetValue(pathLengthOption);
            var crlUrl = parseResult.GetValue(crlUrlOption);
            var ocspUrl = parseResult.GetValue(ocspUrlOption);
            var caIssuersUrl = parseResult.GetValue(caIssuersUrlOption);
            var subjectO = parseResult.GetValue(subjectOOption);
            var subjectOU = parseResult.GetValue(subjectOUOption);
            var subjectC = parseResult.GetValue(subjectCOption);
            var subjectST = parseResult.GetValue(subjectSTOption);
            var subjectL = parseResult.GetValue(subjectLOption);
            var format = parseResult.GetValue(formatOption) ?? "text";
            var formatter = FormatterFactory.Create(format);

            // Validate: if cert or key is specified, both must be specified
            if ((cert != null && key == null) || (cert == null && key != null))
            {
                formatter.WriteError("Both the cert and key parameters should be provided.");
                return;
            }

            // Set default for PFX if no files are specified
            if (pfx == null && cert == null && key == null)
            {
                pfx = new FileInfo("devcert.pfx");
            }

            CertificateCreationResult result;

            if (isCA)
            {
                // Create CA certificate
                var caOptions = new CACertificateOptions
                {
                    Name = dnsNames.FirstOrDefault() ?? "Development CA",
                    Days = days,
                    PathLength = pathLength,
                    KeyType = keyType,
                    KeySize = keySize,
                    HashAlgorithm = hashAlgorithm,
                    RsaPadding = rsaPadding,
                    PfxEncryption = pfxEncryption,
                    CrlUrl = crlUrl,
                    OcspUrl = ocspUrl,
                    CAIssuersUrl = caIssuersUrl,
                    SubjectO = subjectO,
                    SubjectOU = subjectOU,
                    SubjectC = subjectC,
                    SubjectST = subjectST,
                    SubjectL = subjectL,
                    PfxFile = pfx,
                    CertFile = cert,
                    KeyFile = key,
                    Password = password,
                    PasswordFile = passwordFile,
                    Trust = false,
                    TrustLocation = StoreLocation.CurrentUser
                };
                result = await CreateService.CreateCACertificate(caOptions);
            }
            else
            {
                // Create development certificate
                var devOptions = new DevCertificateOptions
                {
                    Domain = dnsNames.FirstOrDefault() ?? "*.dev.local",
                    AdditionalSANs = dnsNames.Skip(1).ToArray(),
                    Days = days,
                    KeyType = keyType,
                    KeySize = keySize,
                    HashAlgorithm = hashAlgorithm,
                    RsaPadding = rsaPadding,
                    PfxEncryption = pfxEncryption,
                    SubjectO = subjectO,
                    SubjectOU = subjectOU,
                    SubjectC = subjectC,
                    SubjectST = subjectST,
                    SubjectL = subjectL,
                    PfxFile = pfx,
                    CertFile = cert,
                    KeyFile = key,
                    Password = password,
                    PasswordFile = passwordFile,
                    Trust = false,
                    TrustLocation = StoreLocation.CurrentUser
                };
                result = await CreateService.CreateDevCertificate(devOptions);
            }

            formatter.WriteCertificateCreated(result);
        });
    }
}
