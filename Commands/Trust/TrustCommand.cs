using certz.Formatters;
using certz.Options;
using certz.Services;
using Spectre.Console;

namespace certz.Commands.Trust;

/// <summary>
/// The trust command for trust store management.
/// </summary>
internal static class TrustCommand
{
    /// <summary>
    /// Adds the trust command to the root command.
    /// </summary>
    internal static void AddTrustCommand(this RootCommand rootCommand)
    {
        var command = BuildTrustCommand();
        rootCommand.Add(command);
    }

    private static Command BuildTrustCommand()
    {
        var trustCommand = new Command("trust", "Trust store management");
        trustCommand.Add(BuildAddCommand());
        trustCommand.Add(BuildRemoveCommand());
        return trustCommand;
    }

    private static Command BuildAddCommand()
    {
        var fileArgument = new Argument<string>("file")
        {
            Description = "Certificate file to add (PFX, PEM, DER)"
        };

        var passwordOption = OptionBuilders.CreatePasswordOption();

        var storeOption = new Option<string>("--store", "-s")
        {
            Description = "Target store (Root, CA, My, TrustedPeople)",
            DefaultValueFactory = _ => "Root"
        };

        var locationOption = new Option<string>("--location", "-l")
        {
            Description = "Store location (CurrentUser, LocalMachine). LocalMachine requires admin.",
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

        var formatOption = OptionBuilders.CreateFormatOption();

        var command = new Command("add", "Add certificate to trust store")
        {
            fileArgument,
            passwordOption,
            storeOption,
            locationOption,
            formatOption
        };

        command.SetAction((parseResult) =>
        {
            var filePath = parseResult.GetValue(fileArgument)
                ?? throw new ArgumentException("File argument is required.");
            var password = parseResult.GetValue(passwordOption);
            var storeName = parseResult.GetValue(storeOption) ?? "Root";
            var storeLocation = parseResult.GetValue(locationOption) ?? "CurrentUser";
            var format = parseResult.GetValue(formatOption) ?? "text";

            // Verify file exists
            if (!File.Exists(filePath))
            {
                throw new FileNotFoundException($"Certificate file not found: {filePath}", filePath);
            }

            var result = TrustHandler.AddToStore(filePath, password, storeName, storeLocation);

            var formatter = FormatterFactory.Create(format);
            formatter.WriteTrustAdded(result);
        });

        return command;
    }

    private static Command BuildRemoveCommand()
    {
        var thumbprintArgument = new Argument<string?>("thumbprint")
        {
            Description = "Certificate thumbprint to remove (full 40-char or partial 8+ char prefix). Optional if --subject is used.",
            Arity = ArgumentArity.ZeroOrOne
        };

        var subjectOption = new Option<string?>("--subject")
        {
            Description = "Remove certificates matching subject pattern (wildcards supported)"
        };

        var storeOption = new Option<string>("--store", "-s")
        {
            Description = "Target store (Root, CA, My, TrustedPeople)",
            DefaultValueFactory = _ => "Root"
        };

        var locationOption = new Option<string>("--location", "-l")
        {
            Description = "Store location (CurrentUser, LocalMachine). LocalMachine requires admin.",
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

        var forceOption = new Option<bool>("--force", "-f")
        {
            Description = "Remove without confirmation (required when multiple certificates match)",
            DefaultValueFactory = _ => false
        };

        var formatOption = OptionBuilders.CreateFormatOption();

        var command = new Command("remove", "Remove certificate from trust store")
        {
            thumbprintArgument,
            subjectOption,
            storeOption,
            locationOption,
            forceOption,
            formatOption
        };

        command.SetAction((parseResult) =>
        {
            var thumbprint = parseResult.GetValue(thumbprintArgument);
            var subject = parseResult.GetValue(subjectOption);
            var storeName = parseResult.GetValue(storeOption) ?? "Root";
            var storeLocation = parseResult.GetValue(locationOption) ?? "CurrentUser";
            var force = parseResult.GetValue(forceOption);
            var format = parseResult.GetValue(formatOption) ?? "text";

            // Validate that either thumbprint or subject is provided
            if (string.IsNullOrEmpty(thumbprint) && string.IsNullOrEmpty(subject))
            {
                throw new InvalidOperationException("Either thumbprint argument or --subject option must be specified.");
            }

            // Validate thumbprint length and format (minimum 8 characters for partial matching)
            if (!string.IsNullOrEmpty(thumbprint))
            {
                var normalized = thumbprint.Replace(" ", "");
                if (normalized.Length < 8)
                {
                    throw new InvalidOperationException(
                        "Thumbprint must be at least 8 characters for partial matching, or 40 characters for exact match.");
                }
                if (!normalized.All(c => char.IsAsciiHexDigit(c)))
                {
                    throw new InvalidOperationException(
                        "Thumbprint must contain only hexadecimal characters (0-9, A-F).");
                }
            }

            // Find matching certificates
            var matchingCerts = TrustHandler.FindMatchingCertificates(thumbprint, subject, storeName, storeLocation);

            if (matchingCerts.Count == 0)
            {
                throw new InvalidOperationException($"No matching certificates found in {storeLocation}\\{storeName}.");
            }

            var formatter = FormatterFactory.Create(format);

            // Handle multiple matches
            if (matchingCerts.Count > 1 && !force)
            {
                // List matching certificates and require --force
                formatter.WriteMultipleMatchesWarning(matchingCerts);
                // Clean up the cloned certs
                foreach (var cert in matchingCerts)
                {
                    cert.Dispose();
                }
                return 1;
            }

            // Interactive confirmation for single match (text mode only, unless --force)
            if (!force && format.Equals("text", StringComparison.OrdinalIgnoreCase))
            {
                var cert = matchingCerts[0];
                var confirmed = AnsiConsole.Confirm(
                    $"Remove certificate '[bold]{Markup.Escape(GetSimpleName(cert.Subject))}[/]' ({cert.Thumbprint})?",
                    defaultValue: false);

                if (!confirmed)
                {
                    AnsiConsole.MarkupLine("[yellow]Operation cancelled.[/]");
                    // Clean up the cloned certs
                    foreach (var c in matchingCerts)
                    {
                        c.Dispose();
                    }
                    return 1;
                }
            }

            // Perform the removal
            var result = TrustHandler.RemoveFromStore(matchingCerts, storeName, storeLocation);

            formatter.WriteTrustRemoved(result);
            return 0;
        });

        return command;
    }

    /// <summary>
    /// Extracts the CN (Common Name) from a subject string.
    /// </summary>
    private static string GetSimpleName(string subject)
    {
        if (subject.Contains("CN="))
        {
            var cnStart = subject.IndexOf("CN=") + 3;
            var cnEnd = subject.IndexOf(',', cnStart);
            return cnEnd > 0 ? subject.Substring(cnStart, cnEnd - cnStart) : subject.Substring(cnStart);
        }
        return subject;
    }
}
