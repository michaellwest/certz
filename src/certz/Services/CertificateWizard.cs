using certz.Formatters;
using certz.Models;
using certz.Options;
using Spectre.Console;

namespace certz.Services;

/// <summary>
/// Interactive wizard for creating certificates with step-by-step guidance.
/// </summary>
internal static class CertificateWizard
{
    private static readonly Style HelpStyle = new(Color.Grey);
    private static readonly Style HighlightStyle = new(Color.Green);
    private static readonly Style WarningStyle = new(Color.Yellow);

    internal static DevCertificateOptions RunDevCertificateWizard()
    {
        // Welcome header
        WriteWelcome("Development Certificate Wizard",
            "This wizard will guide you through creating a development certificate.",
            "Perfect for local HTTPS testing, API development, and debugging.");

        // Step 1: Domain
        WriteStepHeader(1, 6, "Domain Name");
        WriteHelp(
            "The primary domain for your certificate.",
            "For local development, 'localhost' is recommended.",
            "You can also use custom domains like 'myapp.local' or 'api.dev'.");

        var domain = AnsiConsole.Prompt(
            new TextPrompt<string>("[green]?[/] Primary domain name:")
                .DefaultValue("localhost")
                .ValidationErrorMessage("[red]Domain name cannot be empty[/]")
                .Validate(d => !string.IsNullOrWhiteSpace(d)));

        // Step 2: Additional SANs
        WriteStepHeader(2, 6, "Subject Alternative Names (SANs)");
        WriteHelp(
            "SANs allow your certificate to be valid for multiple domains.",
            "Common additions: 127.0.0.1, ::1, *.localhost",
            "The primary domain is automatically included.");

        var additionalSans = new List<string>();
        var addSans = AnsiConsole.Confirm("[green]?[/] Add additional SANs beyond the primary domain?", defaultValue: false);
        if (addSans)
        {
            AnsiConsole.MarkupLine("[grey]  Enter SANs one per line. Leave empty to finish.[/]");
            while (true)
            {
                var san = AnsiConsole.Prompt(
                    new TextPrompt<string>("    [grey]SAN:[/]")
                        .AllowEmpty());
                if (string.IsNullOrWhiteSpace(san)) break;
                additionalSans.Add(san);
            }
        }

        // Step 3: Validity
        WriteStepHeader(3, 6, "Certificate Validity");
        WriteHelp(
            "How long the certificate should be valid.",
            "Recommended: 90 days (aligns with Let's Encrypt renewals)",
            "Maximum: 398 days (CA/Browser Forum limit for public certs)");

        var days = AnsiConsole.Prompt(
            new TextPrompt<int>("[green]?[/] Validity period (days):")
                .DefaultValue(90)
                .ValidationErrorMessage("[red]Days must be between 1 and 398[/]")
                .Validate(d => d >= 1 && d <= 398));

        // Step 4: Key Type
        WriteStepHeader(4, 6, "Key Algorithm");
        WriteHelp(
            "ECDSA is modern, fast, and optimized for TLS 1.3.",
            "RSA has wider compatibility with older systems.",
            "P-256 (256-bit ECDSA) is recommended for most use cases.");

        var keyType = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title("[green]?[/] Select key algorithm:")
                .AddChoices(new[] {
                    "ECDSA-P256 (Recommended)",
                    "ECDSA-P384",
                    "RSA 3072-bit",
                    "RSA 4096-bit"
                })
                .HighlightStyle(HighlightStyle));

        var (keyTypeValue, keySize) = ParseKeyTypeSelection(keyType);

        // Step 5: Trust Store
        WriteStepHeader(5, 6, "Trust Store Installation");
        WriteHelp(
            "Installing to the trust store makes browsers accept the certificate.",
            "Without this, you'll see security warnings in browsers.",
            "The certificate is added to your Trusted Root store.");

        var trust = AnsiConsole.Confirm("[green]?[/] Install certificate to system trust store?", defaultValue: false);
        var trustLocation = StoreLocation.CurrentUser;

        if (trust)
        {
            trustLocation = AnsiConsole.Prompt(
                new SelectionPrompt<StoreLocation>()
                    .Title("[green]?[/] Trust store location:")
                    .AddChoices(StoreLocation.CurrentUser, StoreLocation.LocalMachine)
                    .UseConverter(loc => loc == StoreLocation.CurrentUser
                        ? "CurrentUser (current user only)"
                        : "LocalMachine (all users, requires admin)")
                    .HighlightStyle(HighlightStyle));

            if (trustLocation == StoreLocation.LocalMachine)
            {
                AnsiConsole.MarkupLine("[yellow]  Note: LocalMachine requires administrator privileges.[/]");
            }
        }

        // Step 6: Output
        WriteStepHeader(6, 6, "Output Files");
        WriteHelp(
            "The PFX file contains both the certificate and private key.",
            "You can also export separate .cer and .key files if needed.");

        var defaultPfxName = $"{domain.Replace("*", "wildcard").Replace(".", "-")}.pfx";
        var pfxPath = AnsiConsole.Prompt(
            new TextPrompt<string>("[green]?[/] Output PFX filename:")
                .DefaultValue(defaultPfxName));

        var exportSeparate = AnsiConsole.Confirm("[green]?[/] Also export separate .cer and .key files?", defaultValue: false);
        FileInfo? certFile = null;
        FileInfo? keyFile = null;
        if (exportSeparate)
        {
            certFile = new FileInfo(Path.ChangeExtension(pfxPath, ".cer"));
            keyFile = new FileInfo(Path.ChangeExtension(pfxPath, ".key"));
        }

        // Password
        var generatePassword = AnsiConsole.Confirm("[green]?[/] Auto-generate secure password?", defaultValue: true);
        string? password = null;
        FileInfo? passwordFile = null;
        if (!generatePassword)
        {
            password = AnsiConsole.Prompt(
                new TextPrompt<string>("[green]?[/] Enter password:")
                    .Secret()
                    .ValidationErrorMessage("[red]Password cannot be empty[/]")
                    .Validate(p => !string.IsNullOrWhiteSpace(p)));
        }
        else
        {
            passwordFile = PromptPasswordFile(pfxPath);
        }

        var options = new DevCertificateOptions
        {
            Domain = domain,
            AdditionalSANs = additionalSans.ToArray(),
            Days = days,
            KeyType = keyTypeValue,
            KeySize = keySize,
            Trust = trust,
            TrustLocation = trustLocation,
            PfxFile = new FileInfo(pfxPath),
            CertFile = certFile,
            KeyFile = keyFile,
            Password = password,
            PasswordFile = passwordFile
        };

        // Summary
        if (!DisplaySummaryAndConfirm(options))
        {
            AnsiConsole.MarkupLine("[yellow]Operation cancelled.[/]");
            throw new OperationCanceledException("Wizard cancelled by user");
        }

        return options;
    }

    internal static CACertificateOptions RunCACertificateWizard()
    {
        // Welcome header
        WriteWelcome("Certificate Authority Wizard",
            "This wizard will guide you through creating a Certificate Authority.",
            "A CA can sign other certificates, creating a chain of trust.");

        // Step 1: CA Name
        WriteStepHeader(1, 5, "CA Identity");
        WriteHelp(
            "The Common Name (CN) identifies your Certificate Authority.",
            "Choose a descriptive name like 'My Development Root CA'.",
            "This name appears in certificate details.");

        var name = AnsiConsole.Prompt(
            new TextPrompt<string>("[green]?[/] CA Common Name:")
                .DefaultValue("Development Root CA")
                .ValidationErrorMessage("[red]CA name cannot be empty[/]")
                .Validate(n => !string.IsNullOrWhiteSpace(n)));

        // Step 2: Validity
        WriteStepHeader(2, 5, "Certificate Validity");
        WriteHelp(
            "CA certificates typically have longer validity periods.",
            "Recommended: 10 years for root CAs, 5 years for intermediate CAs.",
            "Certificates issued by this CA cannot exceed its validity.");

        var days = AnsiConsole.Prompt(
            new TextPrompt<int>("[green]?[/] Validity period (days):")
                .DefaultValue(3650)
                .ValidationErrorMessage("[red]Days must be at least 1[/]")
                .Validate(d => d >= 1));

        // Step 3: Path Length Constraint
        WriteStepHeader(3, 5, "Path Length Constraint");
        WriteHelp(
            "Path length limits how many levels of CAs can exist below this one.",
            "0 = Can only issue end-entity certificates (leaf CA)",
            "1 = Can create one level of intermediate CAs",
            "-1 = No constraint (unlimited depth)");

        var pathLengthChoice = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title("[green]?[/] Path length constraint:")
                .AddChoices(new[] {
                    "No constraint (can create unlimited intermediate CAs)",
                    "0 - Leaf CA only (can only issue end-entity certs)",
                    "1 - One intermediate level allowed",
                    "2 - Two intermediate levels allowed"
                })
                .HighlightStyle(HighlightStyle));

        var pathLength = pathLengthChoice switch
        {
            "0 - Leaf CA only (can only issue end-entity certs)" => 0,
            "1 - One intermediate level allowed" => 1,
            "2 - Two intermediate levels allowed" => 2,
            _ => -1
        };

        // Step 4: Key Type
        WriteStepHeader(4, 5, "Key Algorithm");
        WriteHelp(
            "For CA certificates, stronger keys are recommended.",
            "ECDSA P-384 provides excellent security with good performance.",
            "RSA 4096-bit is a conservative choice for maximum compatibility.");

        var keyType = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title("[green]?[/] Select key algorithm:")
                .AddChoices(new[] {
                    "ECDSA-P384 (Recommended for CA)",
                    "ECDSA-P256",
                    "RSA 4096-bit",
                    "RSA 3072-bit"
                })
                .HighlightStyle(HighlightStyle));

        var (keyTypeValue, keySize) = ParseKeyTypeSelection(keyType);

        // Step 5: Trust Store
        WriteStepHeader(5, 5, "Trust Store Installation");
        WriteHelp(
            "Installing the CA to the trust store enables trust for all certificates it signs.",
            "This is typically desired for development root CAs.",
            "You may see a Windows security prompt.");

        var trust = AnsiConsole.Confirm("[green]?[/] Install CA to trusted root store?", defaultValue: true);
        var trustLocation = StoreLocation.CurrentUser;

        if (trust)
        {
            trustLocation = AnsiConsole.Prompt(
                new SelectionPrompt<StoreLocation>()
                    .Title("[green]?[/] Trust store location:")
                    .AddChoices(StoreLocation.CurrentUser, StoreLocation.LocalMachine)
                    .UseConverter(loc => loc == StoreLocation.CurrentUser
                        ? "CurrentUser (current user only)"
                        : "LocalMachine (all users, requires admin)")
                    .HighlightStyle(HighlightStyle));

            if (trustLocation == StoreLocation.LocalMachine)
            {
                AnsiConsole.MarkupLine("[yellow]  Note: LocalMachine requires administrator privileges.[/]");
            }
        }

        // Output file
        AnsiConsole.WriteLine();
        var defaultPfxName = $"{name.Replace(" ", "-").ToLowerInvariant()}.pfx";
        var pfxPath = AnsiConsole.Prompt(
            new TextPrompt<string>("[green]?[/] Output PFX filename:")
                .DefaultValue(defaultPfxName));

        // Password
        var generatePassword = AnsiConsole.Confirm("[green]?[/] Auto-generate secure password?", defaultValue: true);
        string? password = null;
        FileInfo? passwordFile = null;
        if (!generatePassword)
        {
            password = AnsiConsole.Prompt(
                new TextPrompt<string>("[green]?[/] Enter password:")
                    .Secret()
                    .ValidationErrorMessage("[red]Password cannot be empty[/]")
                    .Validate(p => !string.IsNullOrWhiteSpace(p)));
        }
        else
        {
            passwordFile = PromptPasswordFile(pfxPath);
        }

        var options = new CACertificateOptions
        {
            Name = name,
            Days = days,
            PathLength = pathLength,
            KeyType = keyTypeValue,
            KeySize = keySize,
            Trust = trust,
            TrustLocation = trustLocation,
            PfxFile = new FileInfo(pfxPath),
            Password = password,
            PasswordFile = passwordFile
        };

        // Summary
        if (!DisplayCASummaryAndConfirm(options))
        {
            AnsiConsole.MarkupLine("[yellow]Operation cancelled.[/]");
            throw new OperationCanceledException("Wizard cancelled by user");
        }

        return options;
    }

    private static void WriteWelcome(string title, params string[] description)
    {
        AnsiConsole.WriteLine();

        // Styled title
        var rule = new Rule($"[bold blue]{title}[/]")
        {
            Justification = Justify.Left,
            Style = Style.Parse("blue")
        };
        AnsiConsole.Write(rule);
        AnsiConsole.WriteLine();

        // Description panel
        var panel = new Panel(string.Join("\n", description))
        {
            Border = BoxBorder.Rounded,
            BorderStyle = Style.Parse("grey"),
            Padding = new Padding(1, 0)
        };
        AnsiConsole.Write(panel);
        AnsiConsole.WriteLine();
    }

    private static void WriteStepHeader(int step, int totalSteps, string title)
    {
        AnsiConsole.WriteLine();
        AnsiConsole.Write(new Rule($"[bold]Step {step} of {totalSteps}: {title}[/]")
        {
            Justification = Justify.Left,
            Style = Style.Parse("blue dim")
        });
        AnsiConsole.WriteLine();
    }

    private static void WriteHelp(params string[] lines)
    {
        foreach (var line in lines)
        {
            AnsiConsole.MarkupLine($"[grey]  {line}[/]");
        }
        AnsiConsole.WriteLine();
    }

    private static (string KeyType, int KeySize) ParseKeyTypeSelection(string selection)
    {
        return selection switch
        {
            "ECDSA-P256 (Recommended)" or "ECDSA-P256" => ("ECDSA-P256", 256),
            "ECDSA-P384 (Recommended for CA)" or "ECDSA-P384" => ("ECDSA-P384", 384),
            "RSA 3072-bit" => ("RSA", 3072),
            "RSA 4096-bit" => ("RSA", 4096),
            _ => ("ECDSA-P256", 256)
        };
    }

    private static bool DisplaySummaryAndConfirm(DevCertificateOptions options)
    {
        AnsiConsole.WriteLine();
        AnsiConsole.Write(new Rule("[bold]Summary[/]")
        {
            Justification = Justify.Left,
            Style = Style.Parse("green")
        });
        AnsiConsole.WriteLine();

        var table = new Table()
            .Border(TableBorder.Rounded)
            .BorderColor(Color.Grey)
            .AddColumn(new TableColumn("[bold]Setting[/]").Width(20))
            .AddColumn(new TableColumn("[bold]Value[/]"));

        table.AddRow("Domain", $"[cyan]{options.Domain}[/]");

        var sansDisplay = options.AdditionalSANs.Length > 0
            ? string.Join(", ", options.AdditionalSANs)
            : "[grey](auto: 127.0.0.1, ::1)[/]";
        table.AddRow("Additional SANs", sansDisplay);

        table.AddRow("Validity", $"[cyan]{options.Days}[/] days");
        table.AddRow("Key Algorithm", $"[cyan]{options.KeyType}[/]");
        table.AddRow("Trust Store", options.Trust
            ? $"[green]Yes[/] ({options.TrustLocation})"
            : "[grey]No[/]");
        table.AddRow("Output File", $"[cyan]{options.PfxFile?.Name}[/]");

        if (options.CertFile != null)
        {
            table.AddRow("Certificate File", $"[cyan]{options.CertFile.Name}[/]");
            table.AddRow("Key File", $"[cyan]{options.KeyFile?.Name}[/]");
        }

        table.AddRow("Password", options.Password == null
            ? "[green]Auto-generated[/]"
            : "[grey]User-provided[/]");

        AnsiConsole.Write(table);
        AnsiConsole.WriteLine();

        return AnsiConsole.Confirm("[bold green]Create certificate with these settings?[/]", defaultValue: true);
    }

    private static bool DisplayCASummaryAndConfirm(CACertificateOptions options)
    {
        AnsiConsole.WriteLine();
        AnsiConsole.Write(new Rule("[bold]Summary[/]")
        {
            Justification = Justify.Left,
            Style = Style.Parse("green")
        });
        AnsiConsole.WriteLine();

        var table = new Table()
            .Border(TableBorder.Rounded)
            .BorderColor(Color.Grey)
            .AddColumn(new TableColumn("[bold]Setting[/]").Width(20))
            .AddColumn(new TableColumn("[bold]Value[/]"));

        table.AddRow("CA Name", $"[cyan]{options.Name}[/]");
        table.AddRow("Validity", $"[cyan]{options.Days}[/] days (~{options.Days / 365} years)");

        var pathLengthDisplay = options.PathLength switch
        {
            -1 => "[cyan]No constraint[/]",
            0 => "[cyan]0[/] (leaf CA only)",
            _ => $"[cyan]{options.PathLength}[/]"
        };
        table.AddRow("Path Length", pathLengthDisplay);

        table.AddRow("Key Algorithm", $"[cyan]{options.KeyType}[/]");
        table.AddRow("Trust Store", options.Trust
            ? $"[green]Yes[/] ({options.TrustLocation})"
            : "[grey]No[/]");
        table.AddRow("Output File", $"[cyan]{options.PfxFile?.Name}[/]");
        table.AddRow("Password", options.Password == null
            ? "[green]Auto-generated[/]"
            : "[grey]User-provided[/]");

        AnsiConsole.Write(table);
        AnsiConsole.WriteLine();

        return AnsiConsole.Confirm("[bold green]Create CA certificate with these settings?[/]", defaultValue: true);
    }

    // =========================================================================
    // Global wizard entry point — invoked by `certz --guided`
    // =========================================================================

    internal static async Task RunGlobalWizard(IOutputFormatter formatter)
    {
        WriteWelcome("Certz Interactive Wizard",
            "Welcome to certz guided mode.",
            "Answer a few questions and certz will handle the rest.",
            "Press Ctrl+C at any time to cancel.");

        while (true)
        {
            AnsiConsole.WriteLine();

            var task = AnsiConsole.Prompt(
                new SelectionPrompt<string>()
                    .Title("[bold green]?[/] What would you like to do?")
                    .AddChoiceGroup("Create", new[]
                    {
                        "Create a development certificate",
                        "Create a Certificate Authority (CA)"
                    })
                    .AddChoiceGroup("Inspect & Validate", new[]
                    {
                        "Inspect a certificate",
                        "Lint / validate a certificate"
                    })
                    .AddChoiceGroup("Manage", new[]
                    {
                        "Add certificate to trust store",
                        "Remove certificate from trust store",
                        "Convert certificate format",
                        "Monitor certificates for expiration",
                        "Renew a certificate"
                    })
                    .AddChoices("Exit")
                    .HighlightStyle(HighlightStyle));

            switch (task)
            {
                case "Create a development certificate":
                {
                    var options = RunDevCertificateWizard();
                    if (options.PfxFile == null && options.CertFile == null && options.KeyFile == null)
                        options = options with { PfxFile = new FileInfo($"{options.Domain.Replace("*", "wildcard").Replace(".", "-")}.pfx") };
                    var result = await CreateService.CreateDevCertificate(options);
                    formatter.WriteCertificateCreated(result);
                    break;
                }

                case "Create a Certificate Authority (CA)":
                {
                    var options = RunCACertificateWizard();
                    if (options.PfxFile == null && options.CertFile == null && options.KeyFile == null)
                        options = options with { PfxFile = new FileInfo($"{options.Name.Replace(" ", "-").ToLowerInvariant()}.pfx") };
                    var result = await CreateService.CreateCACertificate(options);
                    formatter.WriteCertificateCreated(result);
                    break;
                }

                case "Inspect a certificate":
                {
                    var (options, sourceType) = RunInspectWizard();
                    var result = sourceType switch
                    {
                        InspectSourceType.Url => await CertificateInspector.InspectUrlAsync(options),
                        InspectSourceType.Store => CertificateInspector.InspectFromStore(options),
                        _ => CertificateInspector.InspectFile(options)
                    };
                    formatter.WriteCertificateInspected(result);
                    break;
                }

                case "Lint / validate a certificate":
                {
                    var (options, sourceType) = RunLintWizard();
                    var result = sourceType switch
                    {
                        InspectSourceType.Url => await LintService.LintUrlAsync(options),
                        InspectSourceType.Store => LintService.LintFromStore(options),
                        _ => LintService.LintFile(options)
                    };
                    formatter.WriteLintResult(result);
                    if (!result.Passed)
                        AnsiConsole.MarkupLine($"[red]  Lint failed with {result.ErrorCount} error(s).[/]");
                    break;
                }

                case "Add certificate to trust store":
                {
                    var (filePath, password, storeName, storeLocation) = RunTrustAddWizard();
                    var result = TrustHandler.AddToStore(filePath, password, storeName, storeLocation);
                    formatter.WriteTrustAdded(result);
                    break;
                }

                case "Remove certificate from trust store":
                {
                    var (thumbprint, storeName, storeLocation) = RunTrustRemoveWizard();
                    var matches = TrustHandler.FindMatchingCertificates(thumbprint, null, storeName, storeLocation);
                    if (matches.Count == 0)
                    {
                        AnsiConsole.MarkupLine($"[red]  No matching certificates found in {storeLocation}\\{storeName}.[/]");
                    }
                    else
                    {
                        var confirmed = AnsiConsole.Confirm(
                            $"[yellow]Remove {matches.Count} certificate(s)?[/]", defaultValue: false);
                        if (confirmed)
                        {
                            var result = TrustHandler.RemoveFromStore(matches, storeName, storeLocation);
                            formatter.WriteTrustRemoved(result);
                        }
                        else
                        {
                            AnsiConsole.MarkupLine("[yellow]  Operation cancelled.[/]");
                            foreach (var c in matches) c.Dispose();
                        }
                    }
                    break;
                }

                case "Convert certificate format":
                {
                    var (options, outputFormat) = RunConvertWizard();
                    var result = outputFormat switch
                    {
                        FormatType.Der => await ConvertService.ConvertToDer(options),
                        FormatType.Pfx => await ConvertService.ConvertToPfxSimple(options),
                        _ => await ConvertService.ConvertToPem(options)
                    };
                    formatter.WriteConversionResult(result);
                    break;
                }

                case "Monitor certificates for expiration":
                {
                    var options = RunMonitorWizard();
                    var result = await MonitorService.MonitorAsync(options);
                    formatter.WriteMonitorResult(result, options.QuietMode);
                    break;
                }

                case "Renew a certificate":
                {
                    var options = RunRenewWizard();
                    var result = await RenewService.RenewCertificate(options);
                    formatter.WriteRenewResult(result);
                    break;
                }

                case "Exit":
                    AnsiConsole.MarkupLine("[grey]Goodbye.[/]");
                    return;
            }

            AnsiConsole.WriteLine();
            var doAnother = AnsiConsole.Confirm("[green]?[/] Do another operation?", defaultValue: false);
            if (!doAnother) break;
        }
    }

    // =========================================================================
    // Inspect wizard
    // =========================================================================

    internal enum InspectSourceType { File, Url, Store }

    internal static (InspectOptions Options, InspectSourceType SourceType) RunInspectWizard()
    {
        WriteWelcome("Inspect Certificate",
            "View detailed information about a certificate from a file, URL, or Windows certificate store.");

        var sourceChoice = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title("[green]?[/] Certificate source:")
                .AddChoices("File (PFX, PEM, DER, CRT)", "URL (HTTPS endpoint)", "Windows Store (thumbprint)")
                .HighlightStyle(HighlightStyle));

        var sourceType = sourceChoice switch
        {
            "URL (HTTPS endpoint)" => InspectSourceType.Url,
            "Windows Store (thumbprint)" => InspectSourceType.Store,
            _ => InspectSourceType.File
        };

        string source;
        string? password = null;
        string? storeName = null;
        string? storeLocation = null;

        switch (sourceType)
        {
            case InspectSourceType.File:
                source = PromptCertificateFile("[green]?[/] Certificate file:");
                var rawPass = AnsiConsole.Prompt(
                    new TextPrompt<string>("[green]?[/] Password (leave blank if none):")
                        .AllowEmpty()
                        .Secret());
                password = string.IsNullOrEmpty(rawPass) ? null : rawPass;
                WriteEquivalentCommand($"certz inspect \"{source}\"{(password != null ? " --password <hidden>" : "")}");
                break;

            case InspectSourceType.Url:
                source = AnsiConsole.Prompt(
                    new TextPrompt<string>("[green]?[/] HTTPS URL (e.g. https://example.com):")
                        .Validate(u => u.StartsWith("https://", StringComparison.OrdinalIgnoreCase)
                            ? ValidationResult.Success()
                            : ValidationResult.Error("[red]URL must start with https://[/]")));
                WriteEquivalentCommand($"certz inspect {source}");
                break;

            default: // Store
                source = AnsiConsole.Prompt(
                    new TextPrompt<string>("[green]?[/] Certificate thumbprint (full 40-char or partial 8+):")
                        .Validate(t => !string.IsNullOrWhiteSpace(t) && t.Length >= 8
                            ? ValidationResult.Success()
                            : ValidationResult.Error("[red]Thumbprint must be at least 8 hex characters[/]")));
                storeName = AnsiConsole.Prompt(
                    new SelectionPrompt<string>()
                        .Title("[green]?[/] Certificate store:")
                        .AddChoices("Root", "My", "CA", "TrustedPeople")
                        .HighlightStyle(HighlightStyle));
                storeLocation = AnsiConsole.Prompt(
                    new SelectionPrompt<string>()
                        .Title("[green]?[/] Store location:")
                        .AddChoices("CurrentUser", "LocalMachine")
                        .HighlightStyle(HighlightStyle));
                WriteEquivalentCommand($"certz inspect {source} --store {storeName} --location {storeLocation}");
                break;
        }

        var showChain = AnsiConsole.Confirm("[green]?[/] Show certificate chain?", defaultValue: false);

        var options = new InspectOptions
        {
            Source = source,
            Password = password,
            ShowChain = showChain,
            StoreName = storeName,
            StoreLocation = storeLocation
        };

        return (options, sourceType);
    }

    // =========================================================================
    // Lint wizard
    // =========================================================================

    internal static (LintOptions Options, InspectSourceType SourceType) RunLintWizard()
    {
        WriteWelcome("Lint Certificate",
            "Validate a certificate against CA/Browser Forum and Mozilla NSS requirements.");

        var sourceChoice = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title("[green]?[/] Certificate source:")
                .AddChoices("File (PFX, PEM, DER, CRT)", "URL (HTTPS endpoint)", "Windows Store (thumbprint)")
                .HighlightStyle(HighlightStyle));

        var sourceType = sourceChoice switch
        {
            "URL (HTTPS endpoint)" => InspectSourceType.Url,
            "Windows Store (thumbprint)" => InspectSourceType.Store,
            _ => InspectSourceType.File
        };

        string source;
        string? password = null;
        string? storeName = null;
        string? storeLocation = null;

        switch (sourceType)
        {
            case InspectSourceType.File:
                source = PromptCertificateFile("[green]?[/] Certificate file:");
                var rawPass = AnsiConsole.Prompt(
                    new TextPrompt<string>("[green]?[/] Password (leave blank if none):")
                        .AllowEmpty()
                        .Secret());
                password = string.IsNullOrEmpty(rawPass) ? null : rawPass;
                break;

            case InspectSourceType.Url:
                source = AnsiConsole.Prompt(
                    new TextPrompt<string>("[green]?[/] HTTPS URL (e.g. https://example.com):")
                        .Validate(u => u.StartsWith("https://", StringComparison.OrdinalIgnoreCase)
                            ? ValidationResult.Success()
                            : ValidationResult.Error("[red]URL must start with https://[/]")));
                break;

            default: // Store
                source = AnsiConsole.Prompt(
                    new TextPrompt<string>("[green]?[/] Certificate thumbprint:")
                        .Validate(t => !string.IsNullOrWhiteSpace(t) && t.Length >= 8
                            ? ValidationResult.Success()
                            : ValidationResult.Error("[red]Thumbprint must be at least 8 hex characters[/]")));
                storeName = AnsiConsole.Prompt(
                    new SelectionPrompt<string>()
                        .Title("[green]?[/] Certificate store:")
                        .AddChoices("Root", "My", "CA", "TrustedPeople")
                        .HighlightStyle(HighlightStyle));
                storeLocation = AnsiConsole.Prompt(
                    new SelectionPrompt<string>()
                        .Title("[green]?[/] Store location:")
                        .AddChoices("CurrentUser", "LocalMachine")
                        .HighlightStyle(HighlightStyle));
                break;
        }

        var policy = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title("[green]?[/] Validation policy:")
                .AddChoices("cabf (CA/Browser Forum)", "mozilla (Mozilla NSS)", "dev (development)", "all (all policies)")
                .HighlightStyle(HighlightStyle));

        var policyKey = policy.Split(' ')[0];

        WriteEquivalentCommand($"certz lint \"{source}\" --policy {policyKey}");

        return (new LintOptions
        {
            Source = source,
            Password = password,
            PolicySet = policyKey,
            StoreName = storeName,
            StoreLocation = storeLocation
        }, sourceType);
    }

    // =========================================================================
    // Trust wizards
    // =========================================================================

    internal static (string FilePath, string? Password, string StoreName, string StoreLocation) RunTrustAddWizard()
    {
        WriteWelcome("Add to Trust Store",
            "Install a certificate into the Windows certificate store.",
            "Trusted certificates are accepted by browsers and other applications.");

        var filePath = PromptCertificateFile("[green]?[/] Certificate file:");

        var rawPass = AnsiConsole.Prompt(
            new TextPrompt<string>("[green]?[/] Password (leave blank if none):")
                .AllowEmpty()
                .Secret());
        var password = string.IsNullOrEmpty(rawPass) ? null : rawPass;

        var storeName = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title("[green]?[/] Target store:")
                .AddChoices("Root (Trusted Root CAs)", "CA (Intermediate CAs)", "My (Personal)", "TrustedPeople")
                .HighlightStyle(HighlightStyle));
        var storeKey = storeName.Split(' ')[0];

        var storeLocation = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title("[green]?[/] Store location:")
                .AddChoices("CurrentUser (current user only)", "LocalMachine (all users, requires admin)")
                .HighlightStyle(HighlightStyle));
        var locationKey = storeLocation.Split(' ')[0];

        if (locationKey == "LocalMachine")
            AnsiConsole.MarkupLine("[yellow]  Note: LocalMachine requires administrator privileges.[/]");

        WriteEquivalentCommand($"certz trust add \"{filePath}\" --store {storeKey} --location {locationKey}");

        return (filePath, password, storeKey, locationKey);
    }

    internal static (string Thumbprint, string StoreName, string StoreLocation) RunTrustRemoveWizard()
    {
        WriteWelcome("Remove from Trust Store",
            "Remove a certificate from the Windows certificate store by thumbprint.");

        var thumbprint = AnsiConsole.Prompt(
            new TextPrompt<string>("[green]?[/] Certificate thumbprint (full 40-char or partial 8+):")
                .Validate(t => !string.IsNullOrWhiteSpace(t) && t.Replace(" ", "").Length >= 8
                    ? ValidationResult.Success()
                    : ValidationResult.Error("[red]Thumbprint must be at least 8 hex characters[/]")));

        var storeName = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title("[green]?[/] Certificate store:")
                .AddChoices("Root", "My", "CA", "TrustedPeople")
                .HighlightStyle(HighlightStyle));

        var storeLocation = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title("[green]?[/] Store location:")
                .AddChoices("CurrentUser", "LocalMachine")
                .HighlightStyle(HighlightStyle));

        WriteEquivalentCommand($"certz trust remove {thumbprint} --store {storeName} --location {storeLocation}");

        return (thumbprint, storeName, storeLocation);
    }

    // =========================================================================
    // Convert wizard
    // =========================================================================

    internal static (ConvertOptions Options, FormatType OutputFormat) RunConvertWizard()
    {
        WriteWelcome("Convert Certificate Format",
            "Convert between PEM, DER, and PFX/PKCS#12 formats.",
            "Input format is detected automatically from the file contents.");

        var inputPath = PromptCertificateFile("[green]?[/] Input certificate file:");

        var targetChoice = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title("[green]?[/] Target format:")
                .AddChoices("PEM (.pem / .crt)", "DER (.der / .cer)", "PFX / PKCS#12 (.pfx)")
                .HighlightStyle(HighlightStyle));

        var outputFormat = targetChoice switch
        {
            "DER (.der / .cer)" => FormatType.Der,
            "PFX / PKCS#12 (.pfx)" => FormatType.Pfx,
            _ => FormatType.Pem
        };

        var formatExt = outputFormat switch
        {
            FormatType.Der => "der",
            FormatType.Pfx => "pfx",
            _ => "pem"
        };

        var autoOutput = FormatDetectionService.GenerateOutputPath(new FileInfo(inputPath), outputFormat);
        var outputPath = AnsiConsole.Prompt(
            new TextPrompt<string>("[green]?[/] Output file path:")
                .DefaultValue(autoOutput));

        string? password = null;
        FileInfo? passwordFile = null;
        if (outputFormat == FormatType.Pfx)
        {
            var rawPass = AnsiConsole.Prompt(
                new TextPrompt<string>("[green]?[/] PFX password (leave blank to auto-generate):")
                    .AllowEmpty()
                    .Secret());
            password = string.IsNullOrEmpty(rawPass) ? null : rawPass;

            if (password == null)
            {
                passwordFile = PromptPasswordFile(outputPath);
            }
        }
        else
        {
            // PFX input may need a password to read
            var rawPass = AnsiConsole.Prompt(
                new TextPrompt<string>("[green]?[/] Source PFX password (leave blank if not a PFX):")
                    .AllowEmpty()
                    .Secret());
            password = string.IsNullOrEmpty(rawPass) ? null : rawPass;
        }

        WriteEquivalentCommand($"certz convert \"{inputPath}\" --to {formatExt} --output \"{outputPath}\"");

        var options = new ConvertOptions
        {
            InputFile = new FileInfo(inputPath),
            OutputFormat = outputFormat,
            OutputFile = new FileInfo(outputPath),
            Password = password,
            PasswordFile = passwordFile
        };

        return (options, outputFormat);
    }

    // =========================================================================
    // Monitor wizard
    // =========================================================================

    internal static MonitorOptions RunMonitorWizard()
    {
        WriteWelcome("Monitor Certificate Expiration",
            "Scan certificate files, directories, or URLs for upcoming expiration.",
            "Enter paths and URLs one per line. Leave blank to finish.");

        var sources = new List<string>();

        while (true)
        {
            var prompt = sources.Count == 0
                ? "[green]?[/] Path, directory, or URL to monitor:"
                : "[green]?[/] Add another (leave blank to finish):";

            var entry = AnsiConsole.Prompt(
                new TextPrompt<string>(prompt)
                    .AllowEmpty());

            if (string.IsNullOrWhiteSpace(entry)) break;
            sources.Add(entry.Trim());
        }

        if (sources.Count == 0)
            throw new OperationCanceledException("No sources specified.");

        var warnDays = AnsiConsole.Prompt(
            new TextPrompt<int>("[green]?[/] Warn when expiring within (days):")
                .DefaultValue(30)
                .ValidationErrorMessage("[red]Must be a positive number[/]")
                .Validate(d => d > 0));

        var quietMode = AnsiConsole.Confirm(
            "[green]?[/] Show only certificates within warning threshold?", defaultValue: false);

        var sourcesArg = string.Join(" ", sources.Select(s => $"\"{s}\""));
        WriteEquivalentCommand($"certz monitor {sourcesArg} --warn {warnDays}{(quietMode ? " --quiet" : "")}");

        return new MonitorOptions
        {
            Sources = sources.ToArray(),
            WarnDays = warnDays,
            QuietMode = quietMode
        };
    }

    // =========================================================================
    // Renew wizard
    // =========================================================================

    internal static RenewOptions RunRenewWizard()
    {
        WriteWelcome("Renew Certificate",
            "Extend the validity of an existing certificate.",
            "Existing parameters (key type, SANs) are detected automatically from the source.");

        var source = PromptCertificateFile(
            "[green]?[/] Source certificate:",
            "Enter thumbprint or path manually...",
            validateExists: false);

        string? password = null;
        if (File.Exists(source))
        {
            var rawPass = AnsiConsole.Prompt(
                new TextPrompt<string>("[green]?[/] Password (leave blank if none):")
                    .AllowEmpty()
                    .Secret());
            password = string.IsNullOrEmpty(rawPass) ? null : rawPass;
        }

        var days = AnsiConsole.Prompt(
            new TextPrompt<int>("[green]?[/] New validity period (days):")
                .DefaultValue(90)
                .ValidationErrorMessage("[red]Days must be between 1 and 398[/]")
                .Validate(d => d >= 1 && d <= 398));

        var keepKey = AnsiConsole.Confirm(
            "[green]?[/] Preserve existing private key (no new key generation)?", defaultValue: false);

        var defaultOutput = File.Exists(source)
            ? Path.Combine(
                Path.GetDirectoryName(source) ?? ".",
                Path.GetFileNameWithoutExtension(source) + "-renewed" + Path.GetExtension(source))
            : source + "-renewed.pfx";

        var outputPath = AnsiConsole.Prompt(
            new TextPrompt<string>("[green]?[/] Output file path:")
                .DefaultValue(defaultOutput));

        WriteEquivalentCommand(
            $"certz renew \"{source}\" --days {days}{(keepKey ? " --keep-key" : "")} --output \"{outputPath}\"");

        return new RenewOptions
        {
            Source = source,
            Password = password,
            Days = days,
            KeepKey = keepKey,
            OutputFile = new FileInfo(outputPath)
        };
    }

    // =========================================================================
    // Shared helpers
    // =========================================================================

    private static readonly string[] CertificateExtensions =
        { "*.pfx", "*.p12", "*.pem", "*.crt", "*.cer", "*.der", "*.key" };

    private static string PromptCertificateFile(
        string title,
        string manualLabel = "Enter path manually...",
        bool validateExists = true)
    {
        var files = CertificateExtensions
            .SelectMany(ext => Directory.GetFiles(".", ext))
            .Select(Path.GetFileName)
            .Where(f => f != null)
            .Cast<string>()
            .OrderBy(f => f, StringComparer.OrdinalIgnoreCase)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (files.Count > 0)
        {
            files.Add(manualLabel);
            var choice = AnsiConsole.Prompt(
                new SelectionPrompt<string>()
                    .Title(title)
                    .AddChoices(files)
                    .HighlightStyle(HighlightStyle));

            if (choice != manualLabel)
                return choice;
        }

        var prompt = new TextPrompt<string>(title);
        if (validateExists)
        {
            prompt.Validate(p => File.Exists(p)
                ? ValidationResult.Success()
                : ValidationResult.Error("[red]File not found[/]"));
        }
        else
        {
            prompt.Validate(p => !string.IsNullOrWhiteSpace(p)
                ? ValidationResult.Success()
                : ValidationResult.Error("[red]Input cannot be empty[/]"));
        }

        return AnsiConsole.Prompt(prompt);
    }

    private static FileInfo? PromptPasswordFile(string defaultBaseName)
    {
        var saveToFile = AnsiConsole.Confirm("[green]?[/] Save password to file?", defaultValue: false);
        if (!saveToFile) return null;

        var defaultPath = Path.ChangeExtension(defaultBaseName, ".password");
        var path = AnsiConsole.Prompt(
            new TextPrompt<string>("[green]?[/] Password file:")
                .DefaultValue(defaultPath));

        return new FileInfo(path);
    }

    private static void WriteEquivalentCommand(string command)
    {
        AnsiConsole.WriteLine();
        AnsiConsole.Write(new Rule("[dim]Equivalent command[/]")
        {
            Justification = Justify.Left,
            Style = Style.Parse("grey dim")
        });
        AnsiConsole.MarkupLine($"  [bold cyan]{Markup.Escape(command)}[/]");
        AnsiConsole.WriteLine();
    }
}
