using certz.Formatters;
using certz.Models;
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
            Description = "Store location (CurrentUser, LocalMachine). Defaults to LocalMachine when running as admin (avoids Root store UI dialog).",
            DefaultValueFactory = _ => (OperatingSystem.IsWindows() && TrustHandler.IsRunningAsAdmin()) ? "LocalMachine" : "CurrentUser"
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
        var dryRunOption = OptionBuilders.CreateDryRunOption();

        var command = new Command("add",
            "Add certificate to trust store\n\n" +
            "Usage:\n" +
            "  certz trust add <file>\n\n" +
            "Examples:\n" +
            "  certz trust add ca.crt\n" +
            "  certz trust add ca.crt --store Root --location CurrentUser\n" +
            "  certz trust add ca.pfx --password mypass")
        {
            fileArgument,
            passwordOption,
            storeOption,
            locationOption,
            formatOption,
            dryRunOption
        };

        command.SetAction((parseResult) =>
        {
            var filePath = parseResult.GetValue(fileArgument)
                ?? throw new ArgumentException("File argument is required.");
            var password = parseResult.GetValue(passwordOption);
            var storeName = parseResult.GetValue(storeOption) ?? "Root";
            var storeLocation = parseResult.GetValue(locationOption)
                ?? ((OperatingSystem.IsWindows() && TrustHandler.IsRunningAsAdmin()) ? "LocalMachine" : "CurrentUser");
            var format = parseResult.GetValue(formatOption) ?? "text";
            var dryRun = parseResult.GetValue(dryRunOption);

            // Verify file exists
            if (!File.Exists(filePath))
            {
                throw new FileNotFoundException($"Certificate file not found: {filePath}", filePath);
            }

            var formatter = FormatterFactory.Create(format);

            // Dry-run: show where the cert would be added without modifying the store
            if (dryRun)
            {
                // Load cert to show details (read-only)
                var certDetails = TryLoadCertificateDetails(filePath, password);
                var details = new List<DryRunDetail>
                {
                    new("File",           Path.GetFileName(filePath)),
                    new("Target Store",   $"{storeLocation}\\{storeName}"),
                };
                if (certDetails != null)
                {
                    details.Add(new("Subject",    certDetails.Subject));
                    details.Add(new("Thumbprint", certDetails.Thumbprint));
                    details.Add(new("Expires",    certDetails.NotAfter.ToUniversalTime().ToString("yyyy-MM-dd") + " UTC"));
                }
                formatter.WriteDryRunResult(new DryRunResult
                {
                    Command = "trust add",
                    Action = $"Add certificate to {storeLocation}\\{storeName}",
                    Details = details.ToArray()
                });
                return;
            }

            var result = TrustHandler.AddToStore(filePath, password, storeName, storeLocation);
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
            Description = "Store location (CurrentUser, LocalMachine). Defaults to LocalMachine when running as admin (avoids Root store UI dialog).",
            DefaultValueFactory = _ => (OperatingSystem.IsWindows() && TrustHandler.IsRunningAsAdmin()) ? "LocalMachine" : "CurrentUser"
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
        var dryRunOption = OptionBuilders.CreateDryRunOption();

        var command = new Command("remove",
            "Remove certificate from trust store\n\n" +
            "Usage:\n" +
            "  certz trust remove [thumbprint]\n\n" +
            "Examples:\n" +
            "  certz trust remove A1B2C3D4\n" +
            "  certz trust remove --subject \"My Dev CA\" --force\n" +
            "  certz trust remove A1B2C3D4 --store Root --location CurrentUser")
        {
            thumbprintArgument,
            subjectOption,
            storeOption,
            locationOption,
            forceOption,
            formatOption,
            dryRunOption
        };

        command.SetAction((parseResult) =>
        {
            var thumbprint = parseResult.GetValue(thumbprintArgument);
            var subject = parseResult.GetValue(subjectOption);
            var storeName = parseResult.GetValue(storeOption) ?? "Root";
            var storeLocation = parseResult.GetValue(locationOption)
                ?? ((OperatingSystem.IsWindows() && TrustHandler.IsRunningAsAdmin()) ? "LocalMachine" : "CurrentUser");
            var force = parseResult.GetValue(forceOption);
            var format = parseResult.GetValue(formatOption) ?? "text";
            var dryRun = parseResult.GetValue(dryRunOption);

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

            // Dry-run: show which certs would be removed without modifying the store
            if (dryRun)
            {
                var certList = matchingCerts.Select(c =>
                    $"{GetSimpleName(c.Subject)} ({c.Thumbprint[..Math.Min(16, c.Thumbprint.Length)]}...)").ToArray();

                var details = new List<DryRunDetail>
                {
                    new("Store",             $"{storeLocation}\\{storeName}"),
                    new("Match Count",       matchingCerts.Count.ToString()),
                    new("Would Remove",      string.Join("; ", certList))
                };

                if (!string.IsNullOrEmpty(thumbprint))
                    details.Insert(1, new("Thumbprint Filter", thumbprint));
                if (!string.IsNullOrEmpty(subject))
                    details.Insert(1, new("Subject Filter", subject));

                foreach (var c in matchingCerts) c.Dispose();

                formatter.WriteDryRunResult(new DryRunResult
                {
                    Command = "trust remove",
                    Action = $"Remove {matchingCerts.Count} certificate(s) from {storeLocation}\\{storeName}",
                    Details = details.ToArray()
                });
                return 0;
            }

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

    /// <summary>
    /// Attempts to load basic cert details from a file for dry-run display. Returns null on failure.
    /// </summary>
    private static X509Certificate2? TryLoadCertificateDetails(string filePath, string? password)
    {
        try
        {
            var ext = Path.GetExtension(filePath).ToLowerInvariant();
            if (ext is ".pfx" or ".p12")
            {
                return password != null
                    ? X509CertificateLoader.LoadPkcs12FromFile(filePath, password)
                    : X509CertificateLoader.LoadPkcs12FromFile(filePath, null);
            }
            return X509CertificateLoader.LoadCertificateFromFile(filePath);
        }
        catch
        {
            return null;
        }
    }
}
