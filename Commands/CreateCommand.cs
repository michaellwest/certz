using certz.Options;
using certz.Services;

namespace certz.Commands;

internal static class CreateCommand
{
    internal static void AddCreateCommand(this RootCommand rootCommand)
    {
        var command = BuildCreateCommand();
        rootCommand.Add(command);
    }

    private static Command BuildCreateCommand()
    {
        var pfxOption = OptionBuilders.CreateFileOption(false, new[] { "--file", "--f", "--pkcs12" });
        var certOption = OptionBuilders.CreateFileOption(false, new[] { "--cert", "--c" });
        var keyOption = OptionBuilders.CreateFileOption(false, new[] { "--key", "--k" });
        var passwordOption = OptionBuilders.CreatePasswordOption();
        var dnsOption = new Option<string[]>("--dns", "--san")
        {
            Description = "SAN for the certificate.",
            DefaultValueFactory = _ => new[] { "*.dev.local", "*.localhost", "*.test" },
            AllowMultipleArgumentsPerToken = true
        };
        var daysOption = OptionBuilders.CreateDaysOption(false);

        var createCommand = new Command("create", "Creates a certificate.");
        createCommand.Options.Add(pfxOption);
        createCommand.Options.Add(passwordOption);
        createCommand.Options.Add(certOption);
        createCommand.Options.Add(keyOption);
        createCommand.Options.Add(dnsOption);
        createCommand.Options.Add(daysOption);

        createCommand.SetAction(async (parseResult) =>
        {
            var pfx = parseResult.GetValue(pfxOption);
            var password = parseResult.GetValue(passwordOption);
            var cert = parseResult.GetValue(certOption);
            var key = parseResult.GetValue(keyOption);
            var dnsNames = parseResult.GetValue(dnsOption);
            var days = parseResult.GetValue(daysOption);
            await CertificateOperations.CreateCertificate(pfx!, password, cert!, key!, dnsNames, days);
        });

        return createCommand;
    }
}
