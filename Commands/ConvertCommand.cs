using certz.Formatters;
using certz.Models;
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
        var formatOption = OptionBuilders.CreateFormatOption();

        var convertCommand = new Command("convert", "Converts between PFX and PEM certificate formats.");
        convertCommand.Options.Add(certOption);
        convertCommand.Options.Add(keyOption);
        convertCommand.Options.Add(pfxOption);
        convertCommand.Options.Add(passwordOption);
        convertCommand.Options.Add(passwordFileOption);
        convertCommand.Options.Add(outputCertOption);
        convertCommand.Options.Add(outputKeyOption);
        convertCommand.Options.Add(pfxEncryptionOption);
        convertCommand.Options.Add(formatOption);

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
            var format = parseResult.GetValue(formatOption) ?? "text";
            var formatter = FormatterFactory.Create(format);

            // Determine conversion direction
            if (cert != null && key != null && pfx != null)
            {
                // PEM to PFX (using modern V2 API)
                var options = new ConvertToPfxOptions
                {
                    CertFile = cert,
                    KeyFile = key,
                    OutputFile = pfx,
                    Password = password,
                    PasswordFile = passwordFile,
                    PfxEncryption = pfxEncryption ?? "modern"
                };
                var result = await ConvertService.ConvertToPfx(options);
                formatter.WriteConversionResult(result);
            }
            else if (pfx != null && (outCert != null || outKey != null))
            {
                // PFX to PEM (using modern V2 API)
                // Read password from file if --password-file is specified
                if (string.IsNullOrEmpty(password) && passwordFile != null && passwordFile.Exists)
                {
                    password = (await File.ReadAllTextAsync(passwordFile.FullName)).Trim();
                }

                if (string.IsNullOrEmpty(password))
                {
                    throw new ArgumentException("Password is required for PFX file. Use --password or --password-file to specify the password.");
                }

                var options = new ConvertFromPfxOptions
                {
                    PfxFile = pfx,
                    Password = password,
                    OutputCert = outCert,
                    OutputKey = outKey
                };
                var result = await ConvertService.ConvertFromPfx(options);
                formatter.WriteConversionResult(result);
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
