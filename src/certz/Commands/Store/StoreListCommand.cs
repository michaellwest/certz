using certz.Formatters;
using certz.Models;
using certz.Options;
using certz.Services;

namespace certz.Commands.Store;

/// <summary>
/// The store command for certificate store operations.
/// </summary>
internal static class StoreCommand
{
    /// <summary>
    /// Adds the store command to the root command.
    /// </summary>
    internal static void AddStoreCommand(this RootCommand rootCommand)
    {
        var command = BuildStoreCommand();
        rootCommand.Add(command);
    }

    private static Command BuildStoreCommand()
    {
        var storeCommand = new Command("store", "Certificate store operations");
        storeCommand.Add(BuildListCommand());
        return storeCommand;
    }

    private static Command BuildListCommand()
    {
        var storeOption = new Option<string>("--store", "-s")
        {
            Description = "Store name (My, Root, CA, TrustedPeople, TrustedPublisher)",
            DefaultValueFactory = _ => "My"
        };

        var locationOption = new Option<string>("--location", "-l")
        {
            Description = "Store location (CurrentUser, LocalMachine)",
            DefaultValueFactory = _ => "CurrentUser"
        };
        locationOption.Validators.Add(result =>
        {
            var location = result.GetValueOrDefault<string?>();
            if (!string.IsNullOrEmpty(location))
            {
                var normalizedLocation = location.ToLowerInvariant();
                if (normalizedLocation != "currentuser" && normalizedLocation != "localmachine")
                {
                    result.AddError("Store location must be 'CurrentUser' or 'LocalMachine'.");
                }
            }
        });

        var expiredOption = new Option<bool>("--expired")
        {
            Description = "Show only expired certificates",
            DefaultValueFactory = _ => false
        };

        var expiringOption = new Option<int?>("--expiring")
        {
            Description = "Show certificates expiring within N days"
        };

        var formatOption = OptionBuilders.CreateFormatOption();

        var command = new Command("list", "List certificates in a store")
        {
            storeOption,
            locationOption,
            expiredOption,
            expiringOption,
            formatOption
        };

        command.SetAction((parseResult) =>
        {
            var storeName = parseResult.GetValue(storeOption) ?? "My";
            var storeLocation = parseResult.GetValue(locationOption) ?? "CurrentUser";
            var showExpired = parseResult.GetValue(expiredOption);
            var expiringDays = parseResult.GetValue(expiringOption);
            var format = parseResult.GetValue(formatOption) ?? "text";

            var options = new StoreListOptions
            {
                StoreName = storeName,
                StoreLocation = storeLocation,
                ShowExpired = showExpired,
                ExpiringDays = expiringDays
            };

            var result = StoreListHandler.ListCertificates(options);

            var formatter = FormatterFactory.Create(format);
            formatter.WriteStoreList(result);
        });

        return command;
    }
}
