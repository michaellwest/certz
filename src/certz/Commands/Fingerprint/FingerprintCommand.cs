using certz.Formatters;
using certz.Options;
using certz.Services;

namespace certz.Commands.Fingerprint;

/// <summary>
/// The fingerprint command for quickly outputting the SHA-256 (or other) fingerprint of a certificate.
/// </summary>
internal static class FingerprintCommand
{
    internal static void AddFingerprintCommand(this RootCommand rootCommand)
    {
        var command = BuildFingerprintCommand();
        rootCommand.Add(command);
    }

    private static Command BuildFingerprintCommand()
    {
        var sourceArgument = new Argument<string>("source")
        {
            Description = "File path or URL (https://...) of the certificate"
        };

        var algorithmOption = new Option<string>("--algorithm", "-a")
        {
            Description = "Hash algorithm: sha256 (default), sha384, sha512",
            DefaultValueFactory = _ => "sha256"
        };
        algorithmOption.Validators.Add(result =>
        {
            var value = result.GetValueOrDefault<string>()?.ToLowerInvariant();
            if (value != "sha256" && value != "sha384" && value != "sha512")
            {
                result.AddError("Algorithm must be one of: sha256, sha384, sha512.");
            }
        });

        var passwordOption = OptionBuilders.CreatePasswordOption();
        var formatOption = OptionBuilders.CreateFormatOption();

        var command = new Command("fingerprint",
            "Output the fingerprint (hash) of a certificate\n\n" +
            "Usage:\n" +
            "  certz fingerprint <file|url>\n\n" +
            "Examples:\n" +
            "  certz fingerprint cert.pem\n" +
            "  certz fingerprint https://example.com\n" +
            "  certz fingerprint cert.pfx --password mypass\n" +
            "  certz fingerprint cert.pem --algorithm sha512\n" +
            "  certz fingerprint cert.pem --format json")
        {
            sourceArgument,
            algorithmOption,
            passwordOption,
            formatOption
        };

        command.SetAction(async (parseResult) =>
        {
            var source = parseResult.GetValue(sourceArgument)
                ?? throw new ArgumentException("Source argument is required.");
            var algorithm = parseResult.GetValue(algorithmOption) ?? "sha256";
            var password = parseResult.GetValue(passwordOption);
            var format = parseResult.GetValue(formatOption) ?? "text";

            var formatter = FormatterFactory.Create(format);

            Models.FingerprintResult result;

            if (source.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            {
                result = await FingerprintService.FingerprintUrlAsync(source, algorithm);
            }
            else if (File.Exists(source))
            {
                result = FingerprintService.FingerprintFile(source, algorithm, password);
            }
            else
            {
                throw new FileNotFoundException($"File not found: {source}");
            }

            formatter.WriteFingerprintResult(result);
        });

        return command;
    }
}
