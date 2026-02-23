using certz.Exceptions;
using certz.Formatters;
using certz.Models;
using certz.Options;
using certz.Services;

namespace certz.Commands.Diff;

/// <summary>
/// The diff command for comparing two certificates side-by-side.
/// </summary>
internal static class DiffCommand
{
    /// <summary>
    /// Adds the diff command to the root command.
    /// </summary>
    internal static void AddDiffCommand(this RootCommand rootCommand)
    {
        var command = BuildDiffCommand();
        rootCommand.Add(command);
    }

    private static Command BuildDiffCommand()
    {
        var source1Argument = new Argument<string>("source1")
        {
            Description = "First certificate: file path, URL (https://...), or thumbprint"
        };

        var source2Argument = new Argument<string>("source2")
        {
            Description = "Second certificate: file path, URL (https://...), or thumbprint"
        };

        var passwordOption = OptionBuilders.CreatePasswordOption();

        var password2Option = new Option<string>("--password2", "--pass2")
        {
            Description = "Password for the second certificate (PFX files)."
        };

        var storeOption = new Option<string?>("--store", "-s")
        {
            Description = "Certificate store name for source1 (My, Root, CA)"
        };

        var store2Option = new Option<string?>("--store2")
        {
            Description = "Certificate store name for source2 (My, Root, CA)"
        };

        var locationOption = new Option<string?>("--location", "-l")
        {
            Description = "Store location for source1 (CurrentUser or LocalMachine)"
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

        var location2Option = new Option<string?>("--location2")
        {
            Description = "Store location for source2 (CurrentUser or LocalMachine)"
        };
        location2Option.Validators.Add(result =>
        {
            var location = result.GetValueOrDefault<string?>();
            if (!string.IsNullOrEmpty(location))
            {
                var normalizedLocation = location.ToLowerInvariant();
                if (normalizedLocation != "currentuser" && normalizedLocation != "localmachine")
                {
                    result.AddError("Store location2 must be 'CurrentUser' or 'LocalMachine'.");
                }
            }
        });

        var formatOption = OptionBuilders.CreateFormatOption();

        var command = new Command("diff",
            "Compare two certificates side-by-side and highlight differences\n\n" +
            "Usage:\n" +
            "  certz diff <source1> <source2>\n\n" +
            "Examples:\n" +
            "  certz diff old.pem new.pem\n" +
            "  certz diff old.pfx new.pfx --password mypass\n" +
            "  certz diff cert.pem https://example.com\n" +
            "  certz diff old.pem new.pem --format json")
        {
            source1Argument,
            source2Argument,
            passwordOption,
            password2Option,
            storeOption,
            store2Option,
            locationOption,
            location2Option,
            formatOption
        };

        command.SetAction(async (parseResult) =>
        {
            var source1 = parseResult.GetValue(source1Argument)
                ?? throw new ArgumentException("source1 argument is required.");
            var source2 = parseResult.GetValue(source2Argument)
                ?? throw new ArgumentException("source2 argument is required.");
            var password = parseResult.GetValue(passwordOption);
            var password2 = parseResult.GetValue(password2Option);
            var storeName = parseResult.GetValue(storeOption);
            var storeName2 = parseResult.GetValue(store2Option);
            var storeLocation = parseResult.GetValue(locationOption);
            var storeLocation2 = parseResult.GetValue(location2Option);
            var format = parseResult.GetValue(formatOption) ?? "text";

            var formatter = FormatterFactory.Create(format);

            var options = new DiffOptions
            {
                Source1 = source1,
                Source2 = source2,
                Password1 = password,
                Password2 = password2,
                StoreName1 = storeName,
                StoreName2 = storeName2,
                StoreLocation1 = storeLocation,
                StoreLocation2 = storeLocation2
            };

            var result = await DiffService.CompareCertificatesAsync(options);

            formatter.WriteDiffResult(result);

            // Throw a silent exception to signal exit code 1 when differences are found.
            // Environment.ExitCode does not reliably propagate in async handlers (see CLAUDE.md).
            if (!result.AreIdentical)
            {
                throw new DiffHasDifferencesException(
                    $"{result.DifferenceCount} difference(s) found between the two certificates.");
            }
        });

        return command;
    }
}
