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
        // === New simplified interface arguments/options ===
        var inputArgument = new Argument<FileInfo?>("input")
        {
            Description = "Input certificate file (format auto-detected)",
            Arity = ArgumentArity.ZeroOrOne
        };

        var toOption = new Option<string?>("--to", "-t")
        {
            Description = "Output format: pem, der, pfx"
        };
        toOption.Validators.Add(result =>
        {
            var value = result.GetValueOrDefault<string?>();
            if (value != null && FormatDetectionService.ParseFormat(value) == FormatType.Unknown)
            {
                result.AddError("--to must be one of: pem, der, pfx");
            }
        });

        var outputOption = new Option<FileInfo?>("--output", "-o")
        {
            Description = "Output file path (default: auto-generated from input)"
        };

        var includeKeyOption = new Option<bool>("--include-key")
        {
            Description = "Include private key in output (default: true for PFX)",
            DefaultValueFactory = _ => true
        };

        // === Legacy interface options (kept for backward compatibility) ===
        var certOption = OptionBuilders.CreateFileOption(false, new[] { "--cert", "--c" });
        var keyOption = OptionBuilders.CreateFileOption(false, new[] { "--key", "--k" });
        var pfxOption = OptionBuilders.CreateFileOption(false, new[] { "--file", "--f", "--pfx" });
        var passwordOption = OptionBuilders.CreatePasswordOption();
        var passwordFileOption = OptionBuilders.CreatePasswordFileOption();
        var outputCertOption = OptionBuilders.CreateOutputCertOption();
        var outputKeyOption = OptionBuilders.CreateOutputKeyOption();
        var pfxEncryptionOption = OptionBuilders.CreatePfxEncryptionOption();
        var formatOption = OptionBuilders.CreateFormatOption();

        var convertCommand = new Command("convert",
            "Converts between certificate formats (PEM, DER, PFX).\n\n" +
            "Examples:\n" +
            "  certz convert server.pfx --to pem -p secret\n" +
            "  certz convert server.pem --to der\n" +
            "  certz convert server.der --to pfx --key server.key");

        // Add new interface
        convertCommand.Arguments.Add(inputArgument);
        convertCommand.Options.Add(toOption);
        convertCommand.Options.Add(outputOption);
        convertCommand.Options.Add(includeKeyOption);

        // Add legacy interface options
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
            var input = parseResult.GetValue(inputArgument);
            var to = parseResult.GetValue(toOption);
            var output = parseResult.GetValue(outputOption);
            var key = parseResult.GetValue(keyOption);
            var password = parseResult.GetValue(passwordOption);
            var passwordFile = parseResult.GetValue(passwordFileOption);
            var pfxEncryption = parseResult.GetValue(pfxEncryptionOption) ?? "modern";
            var includeKey = parseResult.GetValue(includeKeyOption);
            var format = parseResult.GetValue(formatOption) ?? "text";
            var formatter = FormatterFactory.Create(format);

            // Legacy interface options
            var cert = parseResult.GetValue(certOption);
            var pfx = parseResult.GetValue(pfxOption);
            var outCert = parseResult.GetValue(outputCertOption);
            var outKey = parseResult.GetValue(outputKeyOption);

            // Determine which interface is being used
            if (input != null && to != null)
            {
                // === New simplified interface ===
                await HandleSimplifiedConversion(
                    input, to, output, key, password, passwordFile,
                    pfxEncryption, includeKey, formatter);
            }
            else if (cert != null && key != null && pfx != null)
            {
                // === Legacy: PEM to PFX ===
                var options = new ConvertToPfxOptions
                {
                    CertFile = cert,
                    KeyFile = key,
                    OutputFile = pfx,
                    Password = password,
                    PasswordFile = passwordFile,
                    PfxEncryption = pfxEncryption
                };
                var result = await ConvertService.ConvertToPfx(options);
                formatter.WriteConversionResult(result);
            }
            else if (pfx != null && (outCert != null || outKey != null))
            {
                // === Legacy: PFX to PEM ===
                if (string.IsNullOrEmpty(password) && passwordFile?.Exists == true)
                {
                    password = (await File.ReadAllTextAsync(passwordFile.FullName)).Trim();
                }

                if (string.IsNullOrEmpty(password))
                {
                    throw new ArgumentException(
                        "Password is required for PFX file. Use --password or --password-file.");
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
                    "Please specify conversion parameters:\n\n" +
                    "Simplified interface:\n" +
                    "  certz convert <input> --to <pem|der|pfx> [options]\n\n" +
                    "Legacy interface:\n" +
                    "  PEM to PFX: --cert <file> --key <file> --pfx <output>\n" +
                    "  PFX to PEM: --pfx <file> --out-cert <output> --out-key <output>");
            }
        });

        return convertCommand;
    }

    private static async Task HandleSimplifiedConversion(
        FileInfo input,
        string to,
        FileInfo? output,
        FileInfo? key,
        string? password,
        FileInfo? passwordFile,
        string pfxEncryption,
        bool includeKey,
        IOutputFormatter formatter)
    {
        if (!input.Exists)
        {
            throw new FileNotFoundException($"Input file not found: {input.FullName}");
        }

        var inputFormat = await FormatDetectionService.DetectFormat(input);
        var outputFormat = FormatDetectionService.ParseFormat(to);

        if (inputFormat == FormatType.Unknown)
        {
            throw new ArgumentException($"Unable to detect format of {input.Name}. Check file content.");
        }

        if (inputFormat == outputFormat)
        {
            throw new ArgumentException(
                $"Input and output formats are the same ({inputFormat}). No conversion needed.");
        }

        var options = new ConvertOptions
        {
            InputFile = input,
            InputFormat = inputFormat,
            OutputFormat = outputFormat,
            OutputFile = output,
            KeyFile = key,
            Password = password,
            PasswordFile = passwordFile,
            PfxEncryption = pfxEncryption,
            IncludeKey = includeKey
        };

        var result = outputFormat switch
        {
            FormatType.Pem => await ConvertService.ConvertToPem(options),
            FormatType.Der => await ConvertService.ConvertToDer(options),
            FormatType.Pfx => await ConvertService.ConvertToPfxSimple(options),
            _ => throw new ArgumentException($"Unsupported output format: {to}")
        };

        formatter.WriteConversionResult(result);
    }
}
