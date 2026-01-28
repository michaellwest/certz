using certz.Options;
using certz.Services;

namespace certz.Commands;

internal static class ConvertCommand
{
    internal static void AddConvertCommand(this RootCommand rootCommand)
    {
        var command = BuildConvertCommand();
        rootCommand.Add(command);
    }

    private static Command BuildConvertCommand()
    {
        var certOption = OptionBuilders.CreateFileOption(false, new[] { "--cert", "--c" });
        var keyOption = OptionBuilders.CreateFileOption(false, new[] { "--key", "--k" });
        var pfxOption = OptionBuilders.CreateFileOption(false, new[] { "--file", "--f", "--pfx" });
        var passwordOption = OptionBuilders.CreatePasswordOption();
        var passwordFileOption = OptionBuilders.CreatePasswordFileOption();
        var outputCertOption = OptionBuilders.CreateOutputCertOption();
        var outputKeyOption = OptionBuilders.CreateOutputKeyOption();
        var pfxEncryptionOption = OptionBuilders.CreatePfxEncryptionOption();

        var convertCommand = new Command("convert", "Converts between PFX and PEM certificate formats.");
        convertCommand.Options.Add(certOption);
        convertCommand.Options.Add(keyOption);
        convertCommand.Options.Add(pfxOption);
        convertCommand.Options.Add(passwordOption);
        convertCommand.Options.Add(passwordFileOption);
        convertCommand.Options.Add(outputCertOption);
        convertCommand.Options.Add(outputKeyOption);
        convertCommand.Options.Add(pfxEncryptionOption);

        convertCommand.SetAction(async (parseResult) =>
        {
            var cert = parseResult.GetValue(certOption);
            var key = parseResult.GetValue(keyOption);
            var pfx = parseResult.GetValue(pfxOption);
            var password = parseResult.GetValue(passwordOption);
            var passwordFile = parseResult.GetValue(passwordFileOption);
            var outCert = parseResult.GetValue(outputCertOption);
            var outKey = parseResult.GetValue(outputKeyOption);
            var pfxEncryption = parseResult.GetValue(pfxEncryptionOption);

            // Determine conversion direction
            if (cert != null && key != null && pfx != null)
            {
                // PEM to PFX (original functionality)
                await CertificateOperations.ConvertToPfx(cert, key, pfx, password, passwordFile, pfxEncryption!);
            }
            else if (pfx != null && (outCert != null || outKey != null))
            {
                // PFX to PEM (new functionality)
                await CertificateOperations.ConvertFromPfx(pfx, password, outCert, outKey);
            }
            else
            {
                throw new ArgumentException(
                    "Please specify conversion parameters:\n" +
                    "  PEM to PFX: --cert <file> --key <file> --pfx <output>\n" +
                    "  PFX to PEM: --pfx <file> --out-cert <output> --out-key <output>");
            }
        });

        return convertCommand;
    }
}
