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
        // Source argument - file path, URL, or thumbprint (optional in --guided mode)
        var sourceArgument = new Argument<string?>("source")
        {
            Description = "File path, URL (https://...), or certificate thumbprint",
            Arity = ArgumentArity.ZeroOrOne
        };

        // Options
        var guidedOption = OptionBuilders.CreateGuidedOption();
        var passwordOption = OptionBuilders.CreatePasswordOption();

        var chainOption = new Option<bool>("--chain", "-c")
        {
            Description = "Show certificate chain",
            DefaultValueFactory = _ => false
        };

        var treeOption = new Option<bool>("--tree", "-t")
        {
            Description = "Show detailed tree with key info, SANs, and signatures (requires --chain)",
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

        var saveDirOption = new Option<string?>("--save-dir")
        {
            Description = "Save every certificate in the chain to its own file in this directory (implies --chain)"
        };

        var namingOption = new Option<string>("--naming")
        {
            Description = "Filename scheme for --save-dir: index-cn-thumbprint (default), cn-thumbprint, thumbprint, cn",
            DefaultValueFactory = _ => "index-cn-thumbprint"
        };
        namingOption.CompletionSources.Add(ChainExportService.NamingSchemes);
        namingOption.Validators.Add(result =>
        {
            var naming = result.GetValueOrDefault<string>();
            if (!string.IsNullOrEmpty(naming) &&
                !ChainExportService.NamingSchemes.Contains(naming, StringComparer.OrdinalIgnoreCase))
            {
                result.AddError($"Naming scheme must be one of: {string.Join(", ", ChainExportService.NamingSchemes)}.");
            }
        });

        var forceOption = OptionBuilders.CreateForceOption(
            "Overwrite existing files when using --save-dir");

        // Shared builder keeps the --dr alias consistent with the other commands; the
        // description is narrowed because here it suppresses writes rather than execution.
        var dryRunOption = OptionBuilders.CreateDryRunOption();
        dryRunOption.Description =
            "With --save-dir, report the files that would be written without writing them";

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
            guidedOption,
            passwordOption,
            chainOption,
            treeOption,
            crlOption,
            warnOption,
            saveOption,
            saveKeyOption,
            saveFormatOption,
            saveDirOption,
            namingOption,
            forceOption,
            dryRunOption,
            storeOption,
            locationOption,
            formatOption
        };

        command.SetAction(async (parseResult) =>
        {
            var guided = parseResult.GetValue(guidedOption);
            var format = parseResult.GetValue(formatOption) ?? "text";
            var formatter = FormatterFactory.Create(format);

            InspectOptions options;
            InspectSource sourceType;

            if (guided)
            {
                try
                {
                    var (wizardOptions, wizardSourceType) = CertificateWizard.RunInspectWizard();
                    options = wizardOptions;
                    sourceType = wizardSourceType switch
                    {
                        CertificateWizard.InspectSourceType.Url => InspectSource.Url,
                        CertificateWizard.InspectSourceType.Store => InspectSource.Store,
                        _ => InspectSource.File
                    };
                }
                catch (OperationCanceledException)
                {
                    Console.Error.WriteLine("Operation cancelled.");
                    return;
                }
            }
            else
            {
                var source = parseResult.GetValue(sourceArgument)
                    ?? throw new ArgumentException("Source argument is required. Use 'certz inspect <source>' or 'certz inspect --guided'.");
                var password = parseResult.GetValue(passwordOption);
                var showChain = parseResult.GetValue(chainOption);
                var showTree = parseResult.GetValue(treeOption);
                var checkCrl = parseResult.GetValue(crlOption);
                var warnDays = parseResult.GetValue(warnOption);
                var savePath = parseResult.GetValue(saveOption);
                var saveKeyPath = parseResult.GetValue(saveKeyOption);
                var saveFormat = parseResult.GetValue(saveFormatOption) ?? "pem";
                var saveDir = parseResult.GetValue(saveDirOption);
                var naming = parseResult.GetValue(namingOption);
                var force = parseResult.GetValue(forceOption);
                var dryRun = parseResult.GetValue(dryRunOption);
                var storeName = parseResult.GetValue(storeOption);
                var storeLocation = parseResult.GetValue(locationOption);

                // --save writes the inspected certificate, --save-dir writes the whole
                // chain. Combining them is ambiguous rather than additive.
                if (!string.IsNullOrEmpty(saveDir) && !string.IsNullOrEmpty(savePath))
                {
                    throw new ArgumentException(
                        "--save-dir and --save are mutually exclusive. Use --save-dir for the full chain, or --save for a single certificate.");
                }

                // --tree implies --chain
                if (showTree && !showChain)
                {
                    showChain = true;
                }

                // --save-dir does not need to force showChain: InspectOptions.NeedsChain
                // derives that, so the two layers cannot fall out of agreement.
                options = new InspectOptions
                {
                    Source = source,
                    Password = password,
                    ShowChain = showChain,
                    DetailedTree = showTree,
                    CheckCrl = checkCrl,
                    WarnDays = warnDays,
                    SavePath = savePath,
                    SaveKeyPath = saveKeyPath,
                    SaveFormat = saveFormat,
                    SaveDir = saveDir,
                    Naming = naming ?? "index-cn-thumbprint",
                    Force = force,
                    DryRun = dryRun,
                    StoreName = storeName,
                    StoreLocation = storeLocation
                };

                sourceType = DetectSourceType(source, storeName);
            }

            var result = sourceType switch
            {
                InspectSource.Url => await CertificateInspector.InspectUrlAsync(options),
                InspectSource.Store => CertificateInspector.InspectFromStore(options),
                InspectSource.File => CertificateInspector.InspectFile(options),
                _ => throw new InvalidOperationException($"Unknown source type for: {options.Source}")
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
