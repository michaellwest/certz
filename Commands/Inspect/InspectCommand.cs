using certz.Formatters;
using certz.Models;
using certz.Options;
using certz.Services;

namespace certz.Commands.Inspect;

/// <summary>
/// The inspect command for viewing certificate details from files, URLs, or certificate stores.
/// </summary>
internal static class InspectCommand
{
    /// <summary>
    /// Adds the inspect command to the root command.
    /// </summary>
    internal static void AddInspectCommand(this RootCommand rootCommand)
    {
        var command = BuildInspectCommand();
        rootCommand.Add(command);
    }

    private static Command BuildInspectCommand()
    {
        // Source argument - file path, URL, or thumbprint
        var sourceArgument = new Argument<string>("source")
        {
            Description = "File path, URL (https://...), or certificate thumbprint"
        };

        // Options
        var passwordOption = OptionBuilders.CreatePasswordOption();

        var chainOption = new Option<bool>("--chain", "-c")
        {
            Description = "Show certificate chain",
            DefaultValueFactory = _ => false
        };

        var crlOption = new Option<bool>("--crl")
        {
            Description = "Check certificate revocation status (OCSP preferred, CRL fallback)",
            DefaultValueFactory = _ => false
        };

        var warnOption = new Option<int?>("--warn", "-w")
        {
            Description = "Warn if certificate expires within N days"
        };

        var saveOption = new Option<string?>("--save")
        {
            Description = "Save certificate to file"
        };

        var saveKeyOption = new Option<string?>("--save-key")
        {
            Description = "Save private key to file"
        };

        var saveFormatOption = new Option<string>("--save-format")
        {
            Description = "Export format: pem (default) or der",
            DefaultValueFactory = _ => "pem"
        };
        saveFormatOption.Validators.Add(result =>
        {
            var format = result.GetValueOrDefault<string>();
            var normalizedFormat = format?.ToLowerInvariant();
            if (normalizedFormat != "pem" && normalizedFormat != "der")
            {
                result.AddError("Save format must be 'pem' or 'der'.");
            }
        });

        var storeOption = new Option<string?>("--store", "-s")
        {
            Description = "Certificate store name (My, Root, CA) - forces thumbprint lookup even if file exists"
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

        var command = new Command("inspect", "Inspect certificate from file, URL, or certificate store")
        {
            sourceArgument,
            passwordOption,
            chainOption,
            crlOption,
            warnOption,
            saveOption,
            saveKeyOption,
            saveFormatOption,
            storeOption,
            locationOption,
            formatOption
        };

        command.SetAction(async (parseResult) =>
        {
            var source = parseResult.GetValue(sourceArgument)
                ?? throw new ArgumentException("Source argument is required.");
            var password = parseResult.GetValue(passwordOption);
            var showChain = parseResult.GetValue(chainOption);
            var checkCrl = parseResult.GetValue(crlOption);
            var warnDays = parseResult.GetValue(warnOption);
            var savePath = parseResult.GetValue(saveOption);
            var saveKeyPath = parseResult.GetValue(saveKeyOption);
            var saveFormat = parseResult.GetValue(saveFormatOption) ?? "pem";
            var storeName = parseResult.GetValue(storeOption);
            var storeLocation = parseResult.GetValue(locationOption);
            var format = parseResult.GetValue(formatOption) ?? "text";

            var formatter = FormatterFactory.Create(format);

            var options = new InspectOptions
            {
                Source = source,
                Password = password,
                ShowChain = showChain,
                CheckCrl = checkCrl,
                WarnDays = warnDays,
                SavePath = savePath,
                SaveKeyPath = saveKeyPath,
                SaveFormat = saveFormat,
                StoreName = storeName,
                StoreLocation = storeLocation
            };

            // Detect source type and dispatch to appropriate handler
            var sourceType = DetectSourceType(source, storeName);

            var result = sourceType switch
            {
                InspectSource.Url => await CertificateInspector.InspectUrlAsync(options),
                InspectSource.Store => CertificateInspector.InspectFromStore(options),
                InspectSource.File => CertificateInspector.InspectFile(options),
                _ => throw new InvalidOperationException($"Unknown source type for: {source}")
            };

            // Output result using formatter
            formatter.WriteCertificateInspected(result);

            // Return non-zero exit code if there are warnings
            if (result.Warnings.Count > 0)
            {
                Environment.ExitCode = 1;
            }
        });

        return command;
    }

    /// <summary>
    /// Detects the source type based on the source string and options.
    /// </summary>
    /// <param name="source">The source string (file path, URL, or thumbprint).</param>
    /// <param name="storeName">The store name option (if specified, forces thumbprint lookup).</param>
    /// <returns>The detected source type.</returns>
    private static InspectSource DetectSourceType(string source, string? storeName)
    {
        // 1. If source starts with "https://" → URL inspection
        if (source.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            return InspectSource.Url;
        }

        // 2. If --store flag provided → thumbprint lookup (even if file exists)
        if (!string.IsNullOrEmpty(storeName))
        {
            return InspectSource.Store;
        }

        // 3. If file exists at path → file inspection
        if (File.Exists(source))
        {
            return InspectSource.File;
        }

        // 4. If argument is a 40-char hex string and file doesn't exist → thumbprint lookup
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
