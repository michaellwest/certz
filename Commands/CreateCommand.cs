using certz.Commands.Create;
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

        createCommand.SetAction(async (parseResult) =>
        {
            var pfx = parseResult.GetValue(pfxOption);
            var password = parseResult.GetValue(passwordOption);
            var passwordFile = parseResult.GetValue(passwordFileOption);
            var cert = parseResult.GetValue(certOption);
            var key = parseResult.GetValue(keyOption);
            var dnsNames = parseResult.GetValue(dnsOption);
            var days = parseResult.GetValue(daysOption);
            var keySize = parseResult.GetValue(keySizeOption);
            var hashAlgorithm = parseResult.GetValue(hashAlgorithmOption);
            var keyType = parseResult.GetValue(keyTypeOption);
            var rsaPadding = parseResult.GetValue(rsaPaddingOption);
            var pfxEncryption = parseResult.GetValue(pfxEncryptionOption);
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

            await CertificateOperations.CreateCertificate(
                pfx!, password, cert!, key!, dnsNames!, days,
                keySize, hashAlgorithm!, keyType!, rsaPadding!,
                isCA, pathLength, crlUrl, ocspUrl, caIssuersUrl,
                subjectO, subjectOU, subjectC, subjectST, subjectL,
                passwordFile, pfxEncryption!);
        });
    }
}
