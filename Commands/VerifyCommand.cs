using certz.Options;
using certz.Services;

namespace certz.Commands;

internal static class VerifyCommand
{
    internal static void AddVerifyCommand(this RootCommand rootCommand)
    {
        var command = BuildVerifyCommand();
        rootCommand.Add(command);
    }

    private static Command BuildVerifyCommand()
    {
        var fileOption = OptionBuilders.CreateFileOption(false, new[] { "--file", "--f", "--cert", "--c" });
        var thumbprintOption = OptionBuilders.CreateThumbprintOption();
        var passwordOption = OptionBuilders.CreatePasswordOption();
        var storeNameOption = OptionBuilders.CreateStoreNameOption();
        var storeLocationOption = OptionBuilders.CreateStoreLocationOption();
        var checkRevocationOption = new Option<bool>("--check-revocation", "--crl")
        {
            Description = "Check certificate revocation status (requires network access).",
            DefaultValueFactory = _ => false
        };
        var warningDaysOption = new Option<int>("--warning-days", "--warn")
        {
            Description = "Number of days before expiration to show warning.",
            DefaultValueFactory = _ => 30
        };

        var verifyCommand = new Command("verify", "Validates a certificate and checks its trust chain.");
        verifyCommand.Options.Add(fileOption);
        verifyCommand.Options.Add(thumbprintOption);
        verifyCommand.Options.Add(passwordOption);
        verifyCommand.Options.Add(storeNameOption);
        verifyCommand.Options.Add(storeLocationOption);
        verifyCommand.Options.Add(checkRevocationOption);
        verifyCommand.Options.Add(warningDaysOption);

        verifyCommand.SetAction(async (parseResult) =>
        {
            var file = parseResult.GetValue(fileOption);
            var thumbprint = parseResult.GetValue(thumbprintOption);
            var password = parseResult.GetValue(passwordOption);
            var storename = parseResult.GetValue(storeNameOption);
            var storelocation = parseResult.GetValue(storeLocationOption);
            var checkRevocation = parseResult.GetValue(checkRevocationOption);
            var warningDays = parseResult.GetValue(warningDaysOption);

            if (!string.IsNullOrEmpty(thumbprint))
            {
                await CertificateOperations.VerifyCertificate(thumbprint, storename, storelocation, checkRevocation, warningDays);
            }
            else if (file != null)
            {
                await CertificateOperations.VerifyCertificate(file, password, checkRevocation, warningDays);
            }
            else
            {
                throw new ArgumentException("Please specify a certificate source: --file or --thumbprint");
            }
        });

        return verifyCommand;
    }
}
