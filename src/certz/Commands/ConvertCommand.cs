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
        var inputArgument = new Argument<FileInfo?>("input")
        {
            Description = "Input certificate file (format auto-detected: PEM, DER, or PFX)",
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
        toOption.CompletionSources.Add(new[] { "pem", "der", "pfx" });

        var outputOption = new Option<FileInfo?>("--output", "-o")
        {
            Description = "Output file path (default: auto-generated from input filename)"
        };

        var includeKeyOption = new Option<bool>("--include-key")
        {
            Description = "Include private key in output (default: true for PFX, false for PEM/DER)",
            DefaultValueFactory = _ => true
        };

        var keyOption = OptionBuilders.CreateFileOption(false, new[] { "--key", "--k" });
        var passwordOption = OptionBuilders.CreatePasswordOption();
        var passwordFileOption = OptionBuilders.CreatePasswordFileOption();
        var pfxEncryptionOption = OptionBuilders.CreatePfxEncryptionOption();
        var formatOption = OptionBuilders.CreateFormatOption();

        var convertCommand = new Command("convert",
            "Convert between certificate formats (PEM, DER, PFX)\n\n" +
            "Usage:\n" +
            "  certz convert <input> --to <pem|der|pfx>\n\n" +
            "Examples:\n" +
            "  certz convert cert.pem --to pfx\n" +
            "  certz convert cert.pfx --to pem\n" +
            "  certz convert cert.der --to pem --output cert.crt");

        convertCommand.Arguments.Add(inputArgument);
        convertCommand.Options.Add(toOption);
        convertCommand.Options.Add(outputOption);
        convertCommand.Options.Add(includeKeyOption);
        convertCommand.Options.Add(keyOption);
        convertCommand.Options.Add(passwordOption);
        convertCommand.Options.Add(passwordFileOption);
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

            if (input == null || to == null)
            {
                throw new ArgumentException(
                    "Input file and output format are required.\n\n" +
                    "Usage: certz convert <input> --to <pem|der|pfx>\n\n" +
                    "Examples:\n" +
                    "  certz convert cert.pem --to pfx\n" +
                    "  certz convert cert.pfx --to pem\n" +
                    "  certz convert cert.der --to pem --output cert.crt");
            }

            await HandleConversion(input, to, output, key, password, passwordFile,
                pfxEncryption, includeKey, formatter);
        });

        return convertCommand;
    }

    private static async Task HandleConversion(
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
