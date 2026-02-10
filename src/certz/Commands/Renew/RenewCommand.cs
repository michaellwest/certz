using certz.Formatters;
using certz.Models;
using certz.Options;
using certz.Services;

namespace certz.Commands.Renew;

/// <summary>
/// The renew command for extending certificate validity.
/// </summary>
internal static class RenewCommand
{
    /// <summary>
    /// Adds the renew command to the root command.
    /// </summary>
    internal static void AddRenewCommand(this RootCommand rootCommand)
    {
        var command = BuildRenewCommand();
        rootCommand.Add(command);
    }

    private static Command BuildRenewCommand()
    {
        // Source argument
        var sourceArgument = new Argument<string>("source")
        {
            Description = "Existing certificate (file path or thumbprint)"
        };

        // Options
        var daysOption = new Option<int?>("--days", "-d")
        {
            Description = "New validity period in days (default: same as original, max 398)"
        };

        var passwordOption = OptionBuilders.CreatePasswordOption();

        var outOption = new Option<FileInfo?>("--out", "-o")
        {
            Description = "Output file path (default: <original>-renewed.pfx)"
        };

        var outPasswordOption = new Option<string?>("--out-password")
        {
            Description = "Password for output file (generates if not specified)"
        };

        var keepKeyOption = new Option<bool>("--keep-key")
        {
            Description = "Preserve existing private key instead of generating new",
            DefaultValueFactory = _ => false
        };

        var issuerCertOption = OptionBuilders.CreateIssuerCertOption();
        var issuerKeyOption = OptionBuilders.CreateIssuerKeyOption();
        var issuerPasswordOption = OptionBuilders.CreateIssuerPasswordOption();

        var storeOption = new Option<string?>("--store")
        {
            Description = "Certificate store name for thumbprint lookup (My, Root, CA)"
        };

        var locationOption = new Option<string?>("--location", "-l")
        {
            Description = "Store location (CurrentUser, LocalMachine)"
        };

        var formatOption = OptionBuilders.CreateFormatOption();

        var command = new Command("renew", "Renew an existing certificate with extended validity")
        {
            sourceArgument,
            daysOption,
            passwordOption,
            outOption,
            outPasswordOption,
            keepKeyOption,
            issuerCertOption,
            issuerKeyOption,
            issuerPasswordOption,
            storeOption,
            locationOption,
            formatOption
        };

        command.SetAction(async (parseResult) =>
        {
            var source = parseResult.GetValue(sourceArgument)
                ?? throw new ArgumentException("Source argument is required.");
            var format = parseResult.GetValue(formatOption) ?? "text";
            var formatter = FormatterFactory.Create(format);

            var options = new RenewOptions
            {
                Source = source,
                Days = parseResult.GetValue(daysOption),
                Password = parseResult.GetValue(passwordOption),
                OutputFile = parseResult.GetValue(outOption),
                OutputPassword = parseResult.GetValue(outPasswordOption),
                KeepKey = parseResult.GetValue(keepKeyOption),
                IssuerCert = parseResult.GetValue(issuerCertOption),
                IssuerKey = parseResult.GetValue(issuerKeyOption),
                IssuerPassword = parseResult.GetValue(issuerPasswordOption),
                StoreName = parseResult.GetValue(storeOption),
                StoreLocation = parseResult.GetValue(locationOption)
            };

            var result = await RenewService.RenewCertificate(options);
            formatter.WriteRenewResult(result);

            // Return exit code based on result
            if (!result.Success)
            {
                // Exit code 2 for missing issuer (CA-signed cert), 1 for other errors
                return result.ErrorMessage?.Contains("CA") == true ? 2 : 1;
            }
            return 0;
        });

        return command;
    }
}
