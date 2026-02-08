using certz.Formatters;
using certz.Models;
using certz.Options;
using certz.Services;

namespace certz.Commands.Lint;

/// <summary>
/// The lint command for validating certificates against industry standards.
/// </summary>
internal static class LintCommand
{
    /// <summary>
    /// Adds the lint command to the root command.
    /// </summary>
    internal static void AddLintCommand(this RootCommand rootCommand)
    {
        var command = BuildLintCommand();
        rootCommand.Add(command);
    }

    private static Command BuildLintCommand()
    {
        // Source argument - file path, URL, or thumbprint
        var sourceArgument = new Argument<string>("source")
        {
            Description = "File path, URL (https://...), or certificate thumbprint"
        };

        // Options
        var passwordOption = OptionBuilders.CreatePasswordOption();

        var policyOption = new Option<string>("--policy", "-p")
        {
            Description = "Policy set: cabf (default), mozilla, dev, or all",
            DefaultValueFactory = _ => "cabf"
        };
        policyOption.Validators.Add(result =>
        {
            var policy = result.GetValueOrDefault<string>()?.ToLowerInvariant();
            var valid = new[] { "cabf", "mozilla", "dev", "all" };
            if (!valid.Contains(policy))
            {
                result.AddError("Policy must be 'cabf', 'mozilla', 'dev', or 'all'.");
            }
        });

        var severityOption = new Option<string>("--severity", "-s")
        {
            Description = "Minimum severity to report: info (default), warning, or error",
            DefaultValueFactory = _ => "info"
        };
        severityOption.Validators.Add(result =>
        {
            var severity = result.GetValueOrDefault<string>()?.ToLowerInvariant();
            var valid = new[] { "info", "warning", "error" };
            if (!valid.Contains(severity))
            {
                result.AddError("Severity must be 'info', 'warning', or 'error'.");
            }
        });

        var storeOption = new Option<string?>("--store")
        {
            Description = "Certificate store name (My, Root, CA) - forces thumbprint lookup"
        };

        var locationOption = new Option<string?>("--location", "-l")
        {
            Description = "Store location (CurrentUser or LocalMachine)"
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

        var formatOption = OptionBuilders.CreateFormatOption();

        var command = new Command("lint", "Validate certificate against CA/B Forum and Mozilla NSS requirements")
        {
            sourceArgument,
            passwordOption,
            policyOption,
            severityOption,
            storeOption,
            locationOption,
            formatOption
        };

        command.SetAction(async (parseResult) =>
        {
            var source = parseResult.GetValue(sourceArgument)
                ?? throw new ArgumentException("Source argument is required.");
            var password = parseResult.GetValue(passwordOption);
            var policy = parseResult.GetValue(policyOption) ?? "cabf";
            var severityStr = parseResult.GetValue(severityOption) ?? "info";
            var storeName = parseResult.GetValue(storeOption);
            var storeLocation = parseResult.GetValue(locationOption);
            var format = parseResult.GetValue(formatOption) ?? "text";

            var severity = severityStr.ToLowerInvariant() switch
            {
                "warning" => LintSeverity.Warning,
                "error" => LintSeverity.Error,
                _ => LintSeverity.Info
            };

            var formatter = FormatterFactory.Create(format);

            var options = new LintOptions
            {
                Source = source,
                Password = password,
                PolicySet = policy,
                MinSeverity = severity,
                StoreName = storeName,
                StoreLocation = storeLocation
            };

            // Detect source type and dispatch to appropriate handler
            var sourceType = DetectSourceType(source, storeName);

            var result = sourceType switch
            {
                InspectSource.Url => await LintService.LintUrlAsync(options),
                InspectSource.Store => LintService.LintFromStore(options),
                InspectSource.File => LintService.LintFile(options),
                _ => throw new InvalidOperationException($"Unknown source type for: {source}")
            };

            // Output result using formatter
            formatter.WriteLintResult(result);

            // Return non-zero exit code if there are errors
            // Throw an exception that will be caught by Program.cs
            if (!result.Passed)
            {
                throw new LintFailedException($"Lint failed with {result.ErrorCount} error(s)");
            }
        });

        return command;
    }

    /// <summary>
    /// Detects the source type based on the source string and options.
    /// </summary>
    private static InspectSource DetectSourceType(string source, string? storeName)
    {
        // 1. If source starts with "https://" → URL
        if (source.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            return InspectSource.Url;
        }

        // 2. If --store flag provided → thumbprint lookup
        if (!string.IsNullOrEmpty(storeName))
        {
            return InspectSource.Store;
        }

        // 3. If file exists at path → file
        if (File.Exists(source))
        {
            return InspectSource.File;
        }

        // 4. If argument is a 40-char hex string and file doesn't exist → thumbprint
        if (IsValidThumbprint(source))
        {
            return InspectSource.Store;
        }

        // 5. Otherwise → error (file not found)
        throw new FileNotFoundException($"File not found: {source}. If this is a thumbprint, use --store to specify the certificate store.");
    }

    /// <summary>
    /// Checks if a string is a valid certificate thumbprint (40 hex characters).
    /// </summary>
    private static bool IsValidThumbprint(string value)
    {
        if (string.IsNullOrEmpty(value) || value.Length != 40)
        {
            return false;
        }

        return value.All(c => char.IsAsciiHexDigit(c));
    }
}
