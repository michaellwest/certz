using certz.Formatters;
using certz.Models;
using certz.Options;
using certz.Services;

namespace certz.Commands.Monitor;

/// <summary>
/// The monitor command for scanning certificates and identifying expiration issues.
/// </summary>
internal static class MonitorCommand
{
    /// <summary>
    /// Adds the monitor command to the root command.
    /// </summary>
    internal static void AddMonitorCommand(this RootCommand rootCommand)
    {
        var command = BuildMonitorCommand();
        rootCommand.Add(command);
    }

    private static Command BuildMonitorCommand()
    {
        // Sources argument - files, directories, or URLs
        var sourcesArgument = new Argument<string[]>("sources")
        {
            Description = "Files, directories, or URLs to scan",
            Arity = ArgumentArity.ZeroOrMore
        };

        // Warning threshold option
        var warnOption = new Option<int>("--warn", "-w")
        {
            Description = "Warning threshold in days (default: 30)",
            DefaultValueFactory = _ => 30
        };
        warnOption.Validators.Add(result =>
        {
            var days = result.GetValueOrDefault<int>();
            if (days < 0)
            {
                result.AddError("Warning threshold must be a positive number of days.");
            }
        });

        // Recursive option
        var recursiveOption = new Option<bool>("--recursive", "-r")
        {
            Description = "Scan subdirectories for certificate files",
            DefaultValueFactory = _ => false
        };

        // Password option
        var passwordOption = OptionBuilders.CreatePasswordOption();

        // Store option
        var storeOption = new Option<string?>("--store", "-s")
        {
            Description = "Certificate store to scan (My, Root, CA)"
        };

        // Location option
        var locationOption = new Option<string?>("--location", "-l")
        {
            Description = "Store location (CurrentUser, LocalMachine)"
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

        // Quiet option
        var quietOption = new Option<bool>("--quiet", "-q")
        {
            Description = "Only show certificates within warning threshold",
            DefaultValueFactory = _ => false
        };

        // Fail on warning option
        var failOnWarningOption = new Option<bool>("--fail-on-warning")
        {
            Description = "Exit with code 1 if certificates within warning threshold",
            DefaultValueFactory = _ => false
        };

        // Format option
        var formatOption = OptionBuilders.CreateFormatOption();

        var command = new Command("monitor", "Monitor certificates for expiration")
        {
            sourcesArgument,
            warnOption,
            recursiveOption,
            passwordOption,
            storeOption,
            locationOption,
            quietOption,
            failOnWarningOption,
            formatOption
        };

        command.SetAction(async (parseResult) =>
        {
            var sources = parseResult.GetValue(sourcesArgument) ?? [];
            var warnDays = parseResult.GetValue(warnOption);
            var recursive = parseResult.GetValue(recursiveOption);
            var password = parseResult.GetValue(passwordOption);
            var storeName = parseResult.GetValue(storeOption);
            var storeLocation = parseResult.GetValue(locationOption);
            var quiet = parseResult.GetValue(quietOption);
            var failOnWarning = parseResult.GetValue(failOnWarningOption);
            var format = parseResult.GetValue(formatOption) ?? "text";

            // Use environment variable for password if not specified
            password ??= Environment.GetEnvironmentVariable("CERTZ_PASSWORD");

            // Validate that at least one source is provided or store is specified
            if (sources.Length == 0 && string.IsNullOrEmpty(storeName))
            {
                throw new ArgumentException("At least one source (file, directory, or URL) or --store must be specified.");
            }

            var options = new MonitorOptions
            {
                Sources = sources,
                WarnDays = warnDays,
                Recursive = recursive,
                Password = password,
                StoreName = storeName,
                StoreLocation = storeLocation,
                QuietMode = quiet,
                FailOnWarning = failOnWarning
            };

            var result = await MonitorService.MonitorAsync(options);

            var formatter = FormatterFactory.Create(format);
            formatter.WriteMonitorResult(result, quiet);

            // Determine exit code
            if (result.ExpiredCount > 0)
            {
                return 2;
            }
            if (failOnWarning && result.ExpiringCount > 0)
            {
                return 1;
            }
            return 0;
        });

        return command;
    }
}
