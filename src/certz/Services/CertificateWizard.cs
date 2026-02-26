using certz.Formatters;
using certz.Models;
using certz.Options;
using Spectre.Console;
using Spectre.Console.Rendering;
using System.Text;
using System.Text.RegularExpressions;
using static System.Net.Mime.MediaTypeNames;

namespace certz.Services;

/// <summary>
/// Interactive wizard for creating certificates with step-by-step guidance.
/// </summary>
internal static partial class CertificateWizard
{
    private static readonly Style HelpStyle = new(Color.Grey);
    private static readonly Style HighlightStyle = new(Color.Green);
    private static readonly Style WarningStyle = new(Color.Yellow);

    private const string CancelChoice = "[grey50]Cancel[/]";

    /// <summary>
    /// Flow-control exception thrown when the user presses Left arrow to go back a step.
    /// </summary>
    private sealed class WizardBackException : Exception;

    /// <summary>
    /// Reference to the active input wrapper so helpers can toggle back-navigation.
    /// Null when running outside the global wizard (no escape/back interception).
    /// </summary>
    private static EscapeCancellableInput? _activeInput;

    private static void SetBackNavigation(bool enabled)
    {
        if (_activeInput != null)
            _activeInput.BackNavigationEnabled = enabled;
    }

    /// <summary>
    /// Wraps a TextPrompt call, disabling left-arrow back navigation so the arrow
    /// key works for cursor movement within the text field.
    /// </summary>
    private static T PromptText<T>(TextPrompt<T> prompt)
    {
        SetBackNavigation(false);
        try { return AnsiConsole.Prompt(prompt); }
        finally { SetBackNavigation(true); }
    }

    /// <summary>
    /// Throws OperationCanceledException if the selected value is the cancel sentinel.
    /// </summary>
    private static string ThrowIfCancelled(string value)
    {
        if (value == CancelChoice)
            throw new OperationCanceledException("Wizard cancelled by user");
        return value;
    }

    internal static DevCertificateOptions RunDevCertificateWizard()
    {
        // Welcome header
        WriteWelcome("Development Certificate Wizard",
            "This wizard will guide you through creating a development certificate.",
            "Perfect for local HTTPS testing, API development, and debugging.");

        var domain = "localhost";
        var additionalSans = new List<string>();
        var days = 90;
        var keyTypeValue = "ECDSA-P256";
        var keySize = 256;
        var trust = false;
        var trustLocation = StoreLocation.CurrentUser;
        var pfxPath = "";
        var exportSeparate = false;
        FileInfo? certFile = null;
        FileInfo? keyFile = null;
        string? password = null;
        FileInfo? passwordFile = null;

        new WizardRunner("Certz", "Create", "Dev Certificate")
            .AddStep("Domain Name", () =>
            {
                WriteHelp(
                    "The primary domain for your certificate.",
                    "For local development, 'localhost' is recommended.",
                    "You can also use custom domains like 'myapp.local' or 'api.dev'.");

                domain = PromptText(
                    new TextPrompt<string>("[green]?[/] Primary domain name:")
                        .DefaultValue("localhost")
                        .ValidationErrorMessage("[red]Domain name cannot be empty[/]")
                        .Validate(d => !string.IsNullOrWhiteSpace(d)));
            })
            .AddStep("Subject Alternative Names", () =>
            {
                WriteHelp(
                    "SANs allow your certificate to be valid for multiple domains.",
                    "Common additions: 127.0.0.1, ::1, *.localhost",
                    "The primary domain is automatically included.");

                additionalSans = [];
                var addSans = AnsiConsole.Confirm("[green]?[/] Add additional SANs beyond the primary domain?", defaultValue: false);
                if (addSans)
                {
                    SetBackNavigation(false);
                    AnsiConsole.MarkupLine("[grey]  Enter SANs one per line. Leave empty to finish.[/]");
                    while (true)
                    {
                        var san = AnsiConsole.Prompt(
                            new TextPrompt<string>("    [grey]SAN:[/]")
                                .AllowEmpty());
                        if (string.IsNullOrWhiteSpace(san)) break;
                        additionalSans.Add(san);
                    }
                    SetBackNavigation(true);
                }
            })
            .AddStep("Certificate Validity", () =>
            {
                WriteHelp(
                    "How long the certificate should be valid.",
                    "Recommended: 90 days (aligns with Let's Encrypt renewals)",
                    "Maximum: 398 days (CA/Browser Forum limit for public certs)");

                days = PromptText(
                    new TextPrompt<int>("[green]?[/] Validity period (days):")
                        .DefaultValue(90)
                        .ValidationErrorMessage("[red]Days must be between 1 and 398[/]")
                        .Validate(d => d >= 1 && d <= 398));
            })
            .AddStep("Key Algorithm", () =>
            {
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

                (keyTypeValue, keySize) = ParseKeyTypeSelection(keyType);
            })
            .AddStep("Trust Store", () =>
            {
                WriteHelp(
                    "Installing to the trust store makes browsers accept the certificate.",
                    "Without this, you'll see security warnings in browsers.",
                    "The certificate is added to your Trusted Root store.");

                trust = AnsiConsole.Confirm("[green]?[/] Install certificate to system trust store?", defaultValue: false);
                trustLocation = StoreLocation.CurrentUser;

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
            })
            .AddStep("Output Files", () =>
            {
                WriteHelp(
                    "The PFX file contains both the certificate and private key.",
                    "You can also export separate .cer and .key files if needed.");

                var defaultPfxName = $"{domain.Replace("*", "wildcard").Replace(".", "-")}.pfx";
                pfxPath = PromptText(
                    new TextPrompt<string>("[green]?[/] Output PFX filename:")
                        .DefaultValue(defaultPfxName));

                exportSeparate = AnsiConsole.Confirm("[green]?[/] Also export separate .cer and .key files?", defaultValue: false);
                certFile = null;
                keyFile = null;
                if (exportSeparate)
                {
                    certFile = new FileInfo(Path.ChangeExtension(pfxPath, ".cer"));
                    keyFile = new FileInfo(Path.ChangeExtension(pfxPath, ".key"));
                }

                // Password
                var generatePassword = AnsiConsole.Confirm("[green]?[/] Auto-generate secure password?", defaultValue: true);
                password = null;
                passwordFile = null;
                if (!generatePassword)
                {
                    password = PromptText(
                        new TextPrompt<string>("[green]?[/] Enter password:")
                            .Secret()
                            .ValidationErrorMessage("[red]Password cannot be empty[/]")
                            .Validate(p => !string.IsNullOrWhiteSpace(p)));
                }
                else
                {
                    passwordFile = PromptPasswordFile(pfxPath);
                }
            })
            .Run();

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

        var name = "Development Root CA";
        var days = 3650;
        var pathLength = -1;
        var keyTypeValue = "ECDSA-P384";
        var keySize = 384;
        var trust = true;
        var trustLocation = StoreLocation.CurrentUser;
        var pfxPath = "";
        string? password = null;
        FileInfo? passwordFile = null;

        new WizardRunner("Certz", "Create", "Certificate Authority")
            .AddStep("CA Identity", () =>
            {
                WriteHelp(
                    "The Common Name (CN) identifies your Certificate Authority.",
                    "Choose a descriptive name like 'My Development Root CA'.",
                    "This name appears in certificate details.");

                name = PromptText(
                    new TextPrompt<string>("[green]?[/] CA Common Name:")
                        .DefaultValue("Development Root CA")
                        .ValidationErrorMessage("[red]CA name cannot be empty[/]")
                        .Validate(n => !string.IsNullOrWhiteSpace(n)));
            })
            .AddStep("Certificate Validity", () =>
            {
                WriteHelp(
                    "CA certificates typically have longer validity periods.",
                    "Recommended: 10 years for root CAs, 5 years for intermediate CAs.",
                    "Certificates issued by this CA cannot exceed its validity.");

                days = PromptText(
                    new TextPrompt<int>("[green]?[/] Validity period (days):")
                        .DefaultValue(3650)
                        .ValidationErrorMessage("[red]Days must be at least 1[/]")
                        .Validate(d => d >= 1));
            })
            .AddStep("Path Length Constraint", () =>
            {
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

                pathLength = pathLengthChoice switch
                {
                    "0 - Leaf CA only (can only issue end-entity certs)" => 0,
                    "1 - One intermediate level allowed" => 1,
                    "2 - Two intermediate levels allowed" => 2,
                    _ => -1
                };
            })
            .AddStep("Key Algorithm", () =>
            {
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

                (keyTypeValue, keySize) = ParseKeyTypeSelection(keyType);
            })
            .AddStep("Trust Store & Output", () =>
            {
                WriteHelp(
                    "Installing the CA to the trust store enables trust for all certificates it signs.",
                    "This is typically desired for development root CAs.",
                    "You may see a Windows security prompt.");

                trust = AnsiConsole.Confirm("[green]?[/] Install CA to trusted root store?", defaultValue: true);
                trustLocation = StoreLocation.CurrentUser;

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
                pfxPath = PromptText(
                    new TextPrompt<string>("[green]?[/] Output PFX filename:")
                        .DefaultValue(defaultPfxName));

                // Password
                var generatePassword = AnsiConsole.Confirm("[green]?[/] Auto-generate secure password?", defaultValue: true);
                password = null;
                passwordFile = null;
                if (!generatePassword)
                {
                    password = PromptText(
                        new TextPrompt<string>("[green]?[/] Enter password:")
                            .Secret()
                            .ValidationErrorMessage("[red]Password cannot be empty[/]")
                            .Validate(p => !string.IsNullOrWhiteSpace(p)));
                }
                else
                {
                    passwordFile = PromptPasswordFile(pfxPath);
                }
            })
            .Run();

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

    // Follow-up action returned by contextual post-operation menus
    private enum FollowUpAction { MainMenu, Exit, FollowUp }

    /// <summary>
    /// Tracks the last operation's parameters so follow-up actions can reuse
    /// source/password without re-prompting (e.g., "Lint this certificate" after inspect).
    /// </summary>
    private record WizardContext
    {
        public string? Source { get; init; }
        public string? Password { get; init; }
        public string? StoreName { get; init; }
        public string? StoreLocation { get; init; }
        public InspectSourceType? SourceType { get; init; }
        public string? OutputFile { get; init; }
        public string? OutputPassword { get; init; }
    }

    internal static async Task RunGlobalWizard(IOutputFormatter formatter)
    {
        // Wrap the console to intercept Escape/Left arrow key presses during prompts
        var originalConsole = AnsiConsole.Console;
        var input = new EscapeCancellableInput(originalConsole.Input);
        _activeInput = input;
        var escapableConsole = new EscapeCancellableConsole(originalConsole, input);
        AnsiConsole.Console = escapableConsole;

        try
        {
        WriteWelcome("Certz Interactive Wizard",
            "Welcome to certz guided mode.",
            "Answer a few questions and certz will handle the rest.",
            "Press Escape to cancel the current step, or Ctrl+C to exit.");

        // Pending follow-up task set by contextual menus (null = show main menu)
        string? nextTask = null;

        // Store context preserved across operations for store browser loop
        string? pendingStoreName = null;
        string? pendingStoreLocation = null;

        // Context forwarding: tracks last operation's parameters for follow-up reuse
        var ctx = new WizardContext();

        while (true)
        {
            string task;

            if (nextTask != null)
            {
                task = nextTask;
                nextTask = null;
                // Note: pendingStoreName/pendingStoreLocation are set explicitly
                // by follow-up handlers that need them; other handlers clear them.
            }
            else
            {
                // Returning to main menu clears store context and forwarded context
                pendingStoreName = null;
                pendingStoreLocation = null;
                ctx = new WizardContext();
                AnsiConsole.WriteLine();

                task = AnsiConsole.Prompt(
                    new SelectionPrompt<string>()
                        .Title("[bold green]?[/] What would you like to do?")
                        .AddChoiceGroup("Create",
                        [
                            "Create a development certificate",
                            "Create a Certificate Authority (CA)"
                        ])
                        .AddChoiceGroup("Inspect & Validate",
                        [
                            "Inspect a certificate",
                            "Lint / validate a certificate"
                        ])
                        .AddChoiceGroup("Manage",
                        [
                            "List certificates in store",
                            "Add certificate to trust store",
                            "Remove certificate from trust store",
                            "Convert certificate format",
                            "Monitor certificates for expiration",
                            "Renew a certificate"
                        ])
                        .AddChoices("Exit")
                        .HighlightStyle(HighlightStyle));
            }

            try
            {
            switch (task)
            {
                case "Create a development certificate":
                    {
                        var options = RunDevCertificateWizard();
                        if (options.PfxFile == null && options.CertFile == null && options.KeyFile == null)
                            options = options with { PfxFile = new FileInfo($"{options.Domain.Replace("*", "wildcard").Replace(".", "-")}.pfx") };
                        var result = await CreateService.CreateDevCertificate(options);
                        formatter.WriteCertificateCreated(result);

                        ctx = new WizardContext
                        {
                            Source = options.PfxFile?.FullName,
                            Password = result.Password,
                            SourceType = InspectSourceType.File,
                            OutputFile = options.PfxFile?.FullName,
                            OutputPassword = result.Password
                        };

                        var followUp = PromptFollowUp(
                            "Inspect the created certificate",
                            "Create another certificate");
                        switch (followUp)
                        {
                            case FollowUpAction.Exit: return;
                            case FollowUpAction.FollowUp:
                                nextTask = _lastFollowUpChoice switch
                                {
                                    "Inspect the created certificate" => "Inspect a certificate",
                                    "Create another certificate" => "Create a development certificate",
                                    _ => null
                                };
                                break;
                        }
                        break;
                    }

                case "Create a Certificate Authority (CA)":
                    {
                        var options = RunCACertificateWizard();
                        if (options.PfxFile == null && options.CertFile == null && options.KeyFile == null)
                            options = options with { PfxFile = new FileInfo($"{options.Name.Replace(" ", "-").ToLowerInvariant()}.pfx") };
                        var result = await CreateService.CreateCACertificate(options);
                        formatter.WriteCertificateCreated(result);

                        ctx = new WizardContext
                        {
                            Source = options.PfxFile?.FullName,
                            Password = result.Password,
                            SourceType = InspectSourceType.File,
                            OutputFile = options.PfxFile?.FullName,
                            OutputPassword = result.Password
                        };

                        var followUp = PromptFollowUp(
                            "Inspect the created certificate",
                            "Create another certificate");
                        switch (followUp)
                        {
                            case FollowUpAction.Exit: return;
                            case FollowUpAction.FollowUp:
                                nextTask = _lastFollowUpChoice switch
                                {
                                    "Inspect the created certificate" => "Inspect a certificate",
                                    "Create another certificate" => "Create a Certificate Authority (CA)",
                                    _ => null
                                };
                                break;
                        }
                        break;
                    }

                case "Inspect a certificate":
                    {
                        InspectOptions inspectOptions;
                        InspectSourceType inspectSourceType;

                        // If store context is available, skip source selection and browse directly
                        if (pendingStoreName != null && pendingStoreLocation != null)
                        {
                            var thumbprint = BrowseStore(pendingStoreName, pendingStoreLocation, subjectFilter: null);
                            inspectOptions = new InspectOptions
                            {
                                Source = thumbprint,
                                StoreName = pendingStoreName,
                                StoreLocation = pendingStoreLocation,
                                ShowChain = AnsiConsole.Confirm("[green]?[/] Show certificate chain?", defaultValue: false)
                            };
                            inspectSourceType = InspectSourceType.Store;
                            WriteEquivalentCommand($"certz inspect {thumbprint} --store {pendingStoreName} --location {pendingStoreLocation}");
                        }
                        // If context has a file source from a previous operation, use it directly
                        else if (ctx.Source != null && ctx.SourceType == InspectSourceType.File)
                        {
                            inspectOptions = new InspectOptions
                            {
                                Source = ctx.Source,
                                Password = ctx.Password,
                                ShowChain = AnsiConsole.Confirm("[green]?[/] Show certificate chain?", defaultValue: false)
                            };
                            inspectSourceType = InspectSourceType.File;
                            WriteEquivalentCommand($"certz inspect \"{ctx.Source}\"{(ctx.Password != null ? " --password <hidden>" : "")}");
                            ctx = new WizardContext(); // Clear after use
                        }
                        else
                        {
                            (inspectOptions, inspectSourceType) = RunInspectWizard();
                        }

                        var inspectResult = inspectSourceType switch
                        {
                            InspectSourceType.Url => await CertificateInspector.InspectUrlAsync(inspectOptions),
                            InspectSourceType.Store => CertificateInspector.InspectFromStore(inspectOptions),
                            _ => CertificateInspector.InspectFile(inspectOptions)
                        };
                        formatter.WriteCertificateInspected(inspectResult);

                        ctx = new WizardContext
                        {
                            Source = inspectOptions.Source,
                            Password = inspectOptions.Password,
                            StoreName = inspectOptions.StoreName,
                            StoreLocation = inspectOptions.StoreLocation,
                            SourceType = inspectSourceType
                        };

                        // Offer store-specific follow-ups when source was a store
                        var inspectFollowUpChoices = inspectSourceType == InspectSourceType.Store
                            ? new[] { "Lint this certificate", "Inspect another from this store", "Inspect another certificate" }
                            : new[] { "Lint this certificate", "Inspect another certificate" };

                        var inspectFollowUp = PromptFollowUp(inspectFollowUpChoices);
                        switch (inspectFollowUp)
                        {
                            case FollowUpAction.Exit: return;
                            case FollowUpAction.FollowUp:
                                switch (_lastFollowUpChoice)
                                {
                                    case "Lint this certificate":
                                        nextTask = "Lint / validate a certificate";
                                        break;
                                    case "Inspect another from this store":
                                        // Preserve store context for the next iteration
                                        pendingStoreName = inspectOptions.StoreName;
                                        pendingStoreLocation = inspectOptions.StoreLocation;
                                        nextTask = "Inspect a certificate";
                                        break;
                                    case "Inspect another certificate":
                                        ctx = new WizardContext(); // Clear so full wizard runs
                                        nextTask = "Inspect a certificate";
                                        break;
                                }
                                break;
                            default:
                                // Clear store context when going back to main menu
                                pendingStoreName = null;
                                pendingStoreLocation = null;
                                break;
                        }
                        break;
                    }

                case "Lint / validate a certificate":
                    {
                        LintOptions lintOptions;
                        InspectSourceType lintSourceType;

                        // If store context is available, skip source selection and browse directly
                        if (pendingStoreName != null && pendingStoreLocation != null)
                        {
                            var thumbprint = BrowseStore(pendingStoreName, pendingStoreLocation, subjectFilter: null);

                            var policy = AnsiConsole.Prompt(
                                new SelectionPrompt<string>()
                                    .Title("[green]?[/] Validation policy:")
                                    .AddChoices("cabf (CA/Browser Forum)", "mozilla (Mozilla NSS)", "dev (development)", "all (all policies)")
                                    .HighlightStyle(HighlightStyle));
                            var policyKey = policy.Split(' ')[0];

                            lintOptions = new LintOptions
                            {
                                Source = thumbprint,
                                StoreName = pendingStoreName,
                                StoreLocation = pendingStoreLocation,
                                PolicySet = policyKey
                            };
                            lintSourceType = InspectSourceType.Store;
                            WriteEquivalentCommand($"certz lint {thumbprint} --store {pendingStoreName} --location {pendingStoreLocation} --policy {policyKey}");
                        }
                        // If context has source from a previous operation (e.g., inspect → lint this cert)
                        else if (ctx.Source != null && ctx.SourceType != null)
                        {
                            var policy = AnsiConsole.Prompt(
                                new SelectionPrompt<string>()
                                    .Title("[green]?[/] Validation policy:")
                                    .AddChoices("cabf (CA/Browser Forum)", "mozilla (Mozilla NSS)", "dev (development)", "all (all policies)")
                                    .HighlightStyle(HighlightStyle));
                            var policyKey = policy.Split(' ')[0];

                            lintOptions = new LintOptions
                            {
                                Source = ctx.Source,
                                Password = ctx.Password,
                                StoreName = ctx.StoreName,
                                StoreLocation = ctx.StoreLocation,
                                PolicySet = policyKey
                            };
                            lintSourceType = ctx.SourceType.Value;
                            WriteEquivalentCommand($"certz lint \"{ctx.Source}\" --policy {policyKey}");
                            ctx = new WizardContext(); // Clear after use
                        }
                        else
                        {
                            (lintOptions, lintSourceType) = RunLintWizard();
                        }

                        var lintResult = lintSourceType switch
                        {
                            InspectSourceType.Url => await LintService.LintUrlAsync(lintOptions),
                            InspectSourceType.Store => LintService.LintFromStore(lintOptions),
                            _ => LintService.LintFile(lintOptions)
                        };
                        formatter.WriteLintResult(lintResult);
                        if (!lintResult.Passed)
                            AnsiConsole.MarkupLine($"[red]  Lint failed with {lintResult.ErrorCount} error(s).[/]");

                        ctx = new WizardContext
                        {
                            Source = lintOptions.Source,
                            Password = lintOptions.Password,
                            StoreName = lintOptions.StoreName,
                            StoreLocation = lintOptions.StoreLocation,
                            SourceType = lintSourceType
                        };

                        // Offer store-specific follow-ups when source was a store
                        var lintFollowUpChoices = lintSourceType == InspectSourceType.Store
                            ? new[] { "Inspect this certificate (full details)", "Lint another from this store", "Lint another certificate" }
                            : new[] { "Inspect this certificate (full details)", "Lint another certificate" };

                        var lintFollowUp = PromptFollowUp(lintFollowUpChoices);
                        switch (lintFollowUp)
                        {
                            case FollowUpAction.Exit: return;
                            case FollowUpAction.FollowUp:
                                switch (_lastFollowUpChoice)
                                {
                                    case "Inspect this certificate (full details)":
                                        nextTask = "Inspect a certificate";
                                        break;
                                    case "Lint another from this store":
                                        pendingStoreName = lintOptions.StoreName;
                                        pendingStoreLocation = lintOptions.StoreLocation;
                                        nextTask = "Lint / validate a certificate";
                                        break;
                                    case "Lint another certificate":
                                        ctx = new WizardContext(); // Clear so full wizard runs
                                        nextTask = "Lint / validate a certificate";
                                        break;
                                }
                                break;
                            default:
                                pendingStoreName = null;
                                pendingStoreLocation = null;
                                break;
                        }
                        break;
                    }

                case "List certificates in store":
                    {
                        var storeListOptions = RunStoreListWizard();
                        var storeListResult = StoreListHandler.ListCertificates(storeListOptions);
                        formatter.WriteStoreList(storeListResult);

                        var storeListFollowUp = PromptFollowUp(
                            "Inspect a certificate from this store",
                            "Remove a certificate from this store",
                            "List with different filter");
                        switch (storeListFollowUp)
                        {
                            case FollowUpAction.Exit: return;
                            case FollowUpAction.FollowUp:
                                switch (_lastFollowUpChoice)
                                {
                                    case "Inspect a certificate from this store":
                                        pendingStoreName = storeListOptions.StoreName;
                                        pendingStoreLocation = storeListOptions.StoreLocation;
                                        nextTask = "Inspect a certificate";
                                        break;
                                    case "Remove a certificate from this store":
                                        pendingStoreName = storeListOptions.StoreName;
                                        pendingStoreLocation = storeListOptions.StoreLocation;
                                        nextTask = "Remove certificate from trust store";
                                        break;
                                    case "List with different filter":
                                        nextTask = "List certificates in store";
                                        break;
                                }
                                break;
                            default:
                                pendingStoreName = null;
                                pendingStoreLocation = null;
                                break;
                        }
                        break;
                    }

                case "Add certificate to trust store":
                    {
                        var (filePath, password, storeName, storeLocation) = RunTrustAddWizard();
                        var result = TrustHandler.AddToStore(filePath, password, storeName, storeLocation);
                        formatter.WriteTrustAdded(result);

                        ctx = new WizardContext
                        {
                            Source = filePath,
                            Password = password,
                            SourceType = InspectSourceType.File
                        };

                        var followUp = PromptFollowUp(
                            "Inspect the trusted certificate",
                            "Add another certificate");
                        switch (followUp)
                        {
                            case FollowUpAction.Exit: return;
                            case FollowUpAction.FollowUp:
                                nextTask = _lastFollowUpChoice switch
                                {
                                    "Inspect the trusted certificate" => "Inspect a certificate",
                                    "Add another certificate" => "Add certificate to trust store",
                                    _ => null
                                };
                                break;
                        }
                        break;
                    }

                case "Remove certificate from trust store":
                    {
                        string removeThumbprint;
                        string removeStoreName;
                        string removeStoreLocation;

                        // If store context is available, skip store selection and browse directly
                        if (pendingStoreName != null && pendingStoreLocation != null)
                        {
                            removeStoreName = pendingStoreName;
                            removeStoreLocation = pendingStoreLocation;
                            removeThumbprint = BrowseStore(removeStoreName, removeStoreLocation, subjectFilter: null);
                            WriteEquivalentCommand($"certz trust remove {removeThumbprint} --store {removeStoreName} --location {removeStoreLocation}");
                        }
                        else
                        {
                            (removeThumbprint, removeStoreName, removeStoreLocation) = RunTrustRemoveWizard();
                        }

                        var matches = TrustHandler.FindMatchingCertificates(removeThumbprint, null, removeStoreName, removeStoreLocation);
                        if (matches.Count == 0)
                        {
                            AnsiConsole.MarkupLine($"[red]  No matching certificates found in {removeStoreLocation}\\{removeStoreName}.[/]");
                        }
                        else
                        {
                            // Display detailed certificate information
                            DisplayMatchedCertificates(matches);

                            var action = AnsiConsole.Prompt(
                                new SelectionPrompt<string>()
                                    .Title($"[yellow]Found {matches.Count} certificate(s). What would you like to do?[/]")
                                    .AddChoices(
                                        "Confirm removal",
                                        "Save details to file for offline analysis",
                                        "Cancel")
                                    .HighlightStyle(HighlightStyle));

                            switch (action)
                            {
                                case "Confirm removal":
                                {
                                    var result = TrustHandler.RemoveFromStore(matches, removeStoreName, removeStoreLocation);
                                    formatter.WriteTrustRemoved(result);
                                    break;
                                }
                                case "Save details to file for offline analysis":
                                {
                                    SaveRemovalSummary(matches, removeStoreName, removeStoreLocation);
                                    var proceed = AnsiConsole.Confirm("[green]?[/] Proceed with removal?", defaultValue: false);
                                    if (proceed)
                                    {
                                        var result = TrustHandler.RemoveFromStore(matches, removeStoreName, removeStoreLocation);
                                        formatter.WriteTrustRemoved(result);
                                    }
                                    else
                                    {
                                        AnsiConsole.MarkupLine("[yellow]  Operation cancelled.[/]");
                                        foreach (var c in matches) c.Dispose();
                                    }
                                    break;
                                }
                                default:
                                {
                                    AnsiConsole.MarkupLine("[yellow]  Operation cancelled.[/]");
                                    foreach (var c in matches) c.Dispose();
                                    break;
                                }
                            }
                        }

                        var removeFollowUp = PromptFollowUp(
                            "Remove another from this store",
                            "List certificates in store");
                        switch (removeFollowUp)
                        {
                            case FollowUpAction.Exit: return;
                            case FollowUpAction.FollowUp:
                                switch (_lastFollowUpChoice)
                                {
                                    case "Remove another from this store":
                                        pendingStoreName = removeStoreName;
                                        pendingStoreLocation = removeStoreLocation;
                                        nextTask = "Remove certificate from trust store";
                                        break;
                                    case "List certificates in store":
                                        nextTask = "List certificates in store";
                                        break;
                                }
                                break;
                            default:
                                pendingStoreName = null;
                                pendingStoreLocation = null;
                                break;
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

                        ctx = new WizardContext
                        {
                            Source = options.OutputFile?.FullName,
                            SourceType = InspectSourceType.File,
                            OutputFile = options.OutputFile?.FullName
                        };

                        var followUp = PromptFollowUp(
                            "Inspect the converted file",
                            "Convert another certificate");
                        switch (followUp)
                        {
                            case FollowUpAction.Exit: return;
                            case FollowUpAction.FollowUp:
                                nextTask = _lastFollowUpChoice switch
                                {
                                    "Inspect the converted file" => "Inspect a certificate",
                                    "Convert another certificate" => "Convert certificate format",
                                    _ => null
                                };
                                break;
                        }
                        break;
                    }

                case "Monitor certificates for expiration":
                    {
                        var options = RunMonitorWizard();
                        var result = await MonitorService.MonitorAsync(options);
                        formatter.WriteMonitorResult(result, options.QuietMode);

                        var followUp = PromptFollowUp();
                        if (followUp == FollowUpAction.Exit) return;
                        break;
                    }

                case "Renew a certificate":
                    {
                        var options = RunRenewWizard();
                        var result = await RenewService.RenewCertificate(options);
                        formatter.WriteRenewResult(result);

                        ctx = new WizardContext
                        {
                            Source = options.OutputFile?.FullName,
                            SourceType = InspectSourceType.File,
                            OutputFile = options.OutputFile?.FullName
                        };

                        var followUp = PromptFollowUp(
                            "Inspect the renewed certificate",
                            "Renew another certificate");
                        switch (followUp)
                        {
                            case FollowUpAction.Exit: return;
                            case FollowUpAction.FollowUp:
                                nextTask = _lastFollowUpChoice switch
                                {
                                    "Inspect the renewed certificate" => "Inspect a certificate",
                                    "Renew another certificate" => "Renew a certificate",
                                    _ => null
                                };
                                break;
                        }
                        break;
                    }

                case "Exit":
                    AnsiConsole.MarkupLine("[grey]Goodbye.[/]");
                    return;
            }
            }
            catch (OperationCanceledException)
            {
                AnsiConsole.MarkupLine("[yellow]  Operation cancelled.[/]");
                // Clear all context and return to main menu
                nextTask = null;
                pendingStoreName = null;
                pendingStoreLocation = null;
                ctx = new WizardContext();
            }
        }
        }
        finally
        {
            // Restore the original console and clear input reference on exit
            _activeInput = null;
            AnsiConsole.Console = originalConsole;
        }
    }

    // Tracks the specific follow-up choice selected by the user
    private static string? _lastFollowUpChoice;

    /// <summary>
    /// Displays a contextual follow-up menu after an operation completes.
    /// Always includes "Back to main menu" and "Exit" options.
    /// </summary>
    private static FollowUpAction PromptFollowUp(params string[] contextualChoices)
    {
        AnsiConsole.WriteLine();

        var choices = new List<string>(contextualChoices)
        {
            "Back to main menu",
            "Exit"
        };

        var choice = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title("[bold green]?[/] What next?")
                .AddChoices(choices)
                .HighlightStyle(HighlightStyle));

        _lastFollowUpChoice = choice;

        return choice switch
        {
            "Exit" => FollowUpAction.Exit,
            "Back to main menu" => FollowUpAction.MainMenu,
            _ => FollowUpAction.FollowUp
        };
    }

    // =========================================================================
    // Inspect wizard
    // =========================================================================

    internal enum InspectSourceType { File, Url, Store }

    internal static (InspectOptions Options, InspectSourceType SourceType) RunInspectWizard()
    {
        WriteWelcome("Inspect Certificate",
            "View detailed information about a certificate from a file, URL, or Windows certificate store.");

        var sourceType = InspectSourceType.File;
        string source = "";
        string? password = null;
        string? storeName = null;
        string? storeLocation = null;
        var showChain = false;

        new WizardRunner("Certz", "Inspect")
            .AddStep("Certificate Source", () =>
            {
                var sourceChoice = ThrowIfCancelled(AnsiConsole.Prompt(
                    new SelectionPrompt<string>()
                        .Title("[green]?[/] Certificate source:")
                        .AddChoices("File (PFX, PEM, DER, CRT)", "URL (HTTPS endpoint)", "Windows Store (browse or enter thumbprint)", CancelChoice)
                        .HighlightStyle(HighlightStyle)));

                sourceType = sourceChoice switch
                {
                    "URL (HTTPS endpoint)" => InspectSourceType.Url,
                    "Windows Store (browse or enter thumbprint)" => InspectSourceType.Store,
                    _ => InspectSourceType.File
                };

                password = null;
                storeName = null;
                storeLocation = null;

                switch (sourceType)
                {
                    case InspectSourceType.File:
                        source = PromptCertificateFile("[green]?[/] Certificate file:");
                        var rawPass = PromptText(
                            new TextPrompt<string>("[green]?[/] Password (leave blank if none):")
                                .AllowEmpty()
                                .Secret());
                        password = string.IsNullOrEmpty(rawPass) ? null : rawPass;
                        WriteEquivalentCommand($"certz inspect \"{source}\"{(password != null ? " --password <hidden>" : "")}");
                        break;

                    case InspectSourceType.Url:
                        source = PromptUrl();
                        WriteEquivalentCommand($"certz inspect {source}");
                        break;

                    default: // Store
                        storeLocation = ThrowIfCancelled(AnsiConsole.Prompt(
                            new SelectionPrompt<string>()
                                .Title("[green]?[/] Store location:")
                                .AddChoices("CurrentUser", "LocalMachine", CancelChoice)
                                .HighlightStyle(HighlightStyle)));
                        storeName = ThrowIfCancelled(AnsiConsole.Prompt(
                            new SelectionPrompt<string>()
                                .Title("[green]?[/] Certificate store:")
                                .AddChoices("My (Personal)", "Root (Trusted Root CAs)", "CA (Intermediate CAs)", "TrustedPeople", CancelChoice)
                                .HighlightStyle(HighlightStyle)));
                        var inspectStoreKey = storeName.Split(' ')[0];
                        source = BrowseOrEnterThumbprint(inspectStoreKey, storeLocation);
                        storeName = inspectStoreKey;
                        WriteEquivalentCommand($"certz inspect {source} --store {storeName} --location {storeLocation}");
                        break;
                }
            })
            .AddStep("Display Options", () =>
            {
                showChain = AnsiConsole.Confirm("[green]?[/] Show certificate chain?", defaultValue: false);
            })
            .Run();

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

        var sourceType = InspectSourceType.File;
        string source = "";
        string? password = null;
        string? storeName = null;
        string? storeLocation = null;
        var policyKey = "cabf";

        new WizardRunner("Certz", "Lint")
            .AddStep("Certificate Source", () =>
            {
                var sourceChoice = ThrowIfCancelled(AnsiConsole.Prompt(
                    new SelectionPrompt<string>()
                        .Title("[green]?[/] Certificate source:")
                        .AddChoices("File (PFX, PEM, DER, CRT)", "URL (HTTPS endpoint)", "Windows Store (browse or enter thumbprint)", CancelChoice)
                        .HighlightStyle(HighlightStyle)));

                sourceType = sourceChoice switch
                {
                    "URL (HTTPS endpoint)" => InspectSourceType.Url,
                    "Windows Store (browse or enter thumbprint)" => InspectSourceType.Store,
                    _ => InspectSourceType.File
                };

                password = null;
                storeName = null;
                storeLocation = null;

                switch (sourceType)
                {
                    case InspectSourceType.File:
                        source = PromptCertificateFile("[green]?[/] Certificate file:");
                        var rawPass = PromptText(
                            new TextPrompt<string>("[green]?[/] Password (leave blank if none):")
                                .AllowEmpty()
                                .Secret());
                        password = string.IsNullOrEmpty(rawPass) ? null : rawPass;
                        break;

                    case InspectSourceType.Url:
                        source = PromptUrl();
                        break;

                    default: // Store
                        storeLocation = ThrowIfCancelled(AnsiConsole.Prompt(
                            new SelectionPrompt<string>()
                                .Title("[green]?[/] Store location:")
                                .AddChoices("CurrentUser", "LocalMachine", CancelChoice)
                                .HighlightStyle(HighlightStyle)));
                        storeName = ThrowIfCancelled(AnsiConsole.Prompt(
                            new SelectionPrompt<string>()
                                .Title("[green]?[/] Certificate store:")
                                .AddChoices("My (Personal)", "Root (Trusted Root CAs)", "CA (Intermediate CAs)", "TrustedPeople", CancelChoice)
                                .HighlightStyle(HighlightStyle)));
                        var lintStoreKey = storeName.Split(' ')[0];
                        source = BrowseOrEnterThumbprint(lintStoreKey, storeLocation);
                        storeName = lintStoreKey;
                        break;
                }
            })
            .AddStep("Validation Policy", () =>
            {
                var policy = ThrowIfCancelled(AnsiConsole.Prompt(
                    new SelectionPrompt<string>()
                        .Title("[green]?[/] Validation policy:")
                        .AddChoices("cabf (CA/Browser Forum)", "mozilla (Mozilla NSS)", "dev (development)", "all (all policies)", CancelChoice)
                        .HighlightStyle(HighlightStyle)));

                policyKey = policy.Split(' ')[0];

                WriteEquivalentCommand($"certz lint \"{source}\" --policy {policyKey}");
            })
            .Run();

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

        var filePath = "";
        string? password = null;
        var storeKey = "Root";
        var locationKey = "CurrentUser";

        new WizardRunner("Certz", "Trust", "Add")
            .AddStep("Certificate File", () =>
            {
                filePath = PromptCertificateFile("[green]?[/] Certificate file:");

                var rawPass = PromptText(
                    new TextPrompt<string>("[green]?[/] Password (leave blank if none):")
                        .AllowEmpty()
                        .Secret());
                password = string.IsNullOrEmpty(rawPass) ? null : rawPass;
            })
            .AddStep("Target Store", () =>
            {
                var storeName = ThrowIfCancelled(AnsiConsole.Prompt(
                    new SelectionPrompt<string>()
                        .Title("[green]?[/] Target store:")
                        .AddChoices("My (Personal)", "Root (Trusted Root CAs)", "CA (Intermediate CAs)", "TrustedPeople", CancelChoice)
                        .HighlightStyle(HighlightStyle)));
                storeKey = storeName.Split(' ')[0];

                var storeLocation = ThrowIfCancelled(AnsiConsole.Prompt(
                    new SelectionPrompt<string>()
                        .Title("[green]?[/] Store location:")
                        .AddChoices("CurrentUser (current user only)", "LocalMachine (all users, requires admin)", CancelChoice)
                        .HighlightStyle(HighlightStyle)));
                locationKey = storeLocation.Split(' ')[0];

                if (locationKey == "LocalMachine")
                    AnsiConsole.MarkupLine("[yellow]  Note: LocalMachine requires administrator privileges.[/]");

                WriteEquivalentCommand($"certz trust add \"{filePath}\" --store {storeKey} --location {locationKey}");
            })
            .Run();

        return (filePath, password, storeKey, locationKey);
    }

    internal static (string Thumbprint, string StoreName, string StoreLocation) RunTrustRemoveWizard()
    {
        WriteWelcome("Remove from Trust Store",
            "Remove a certificate from the Windows certificate store.",
            "You can browse the store to find the certificate to remove.");

        var storeLocation = "CurrentUser";
        var storeName = "Root";
        var thumbprint = "";

        new WizardRunner("Certz", "Trust", "Remove")
            .AddStep("Store Location", () =>
            {
                storeLocation = ThrowIfCancelled(AnsiConsole.Prompt(
                    new SelectionPrompt<string>()
                        .Title("[green]?[/] Store location:")
                        .AddChoices("CurrentUser", "LocalMachine", CancelChoice)
                        .HighlightStyle(HighlightStyle)));

                var storeNameChoice = ThrowIfCancelled(AnsiConsole.Prompt(
                    new SelectionPrompt<string>()
                        .Title("[green]?[/] Certificate store:")
                        .AddChoices("Root (Trusted Root CAs)", "My (Personal)", "CA (Intermediate CAs)", "TrustedPeople", CancelChoice)
                        .HighlightStyle(HighlightStyle)));
                storeName = storeNameChoice.Split(' ')[0];
            })
            .AddStep("Select Certificate", () =>
            {
                thumbprint = BrowseOrEnterThumbprint(storeName, storeLocation);

                WriteEquivalentCommand($"certz trust remove {thumbprint} --store {storeName} --location {storeLocation}");
            })
            .Run();

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

        var inputPath = "";
        var outputFormat = FormatType.Pem;
        var outputPath = "";
        string? password = null;
        FileInfo? passwordFile = null;

        new WizardRunner("Certz", "Convert")
            .AddStep("Input File", () =>
            {
                inputPath = PromptCertificateFile("[green]?[/] Input certificate file:");
            })
            .AddStep("Target Format", () =>
            {
                var targetChoice = ThrowIfCancelled(AnsiConsole.Prompt(
                    new SelectionPrompt<string>()
                        .Title("[green]?[/] Target format:")
                        .AddChoices("PEM (.pem / .crt)", "DER (.der / .cer)", "PFX / PKCS#12 (.pfx)", CancelChoice)
                        .HighlightStyle(HighlightStyle)));

                outputFormat = targetChoice switch
                {
                    "DER (.der / .cer)" => FormatType.Der,
                    "PFX / PKCS#12 (.pfx)" => FormatType.Pfx,
                    _ => FormatType.Pem
                };
            })
            .AddStep("Output & Password", () =>
            {
                var formatExt = outputFormat switch
                {
                    FormatType.Der => "der",
                    FormatType.Pfx => "pfx",
                    _ => "pem"
                };

                var autoOutput = FormatDetectionService.GenerateOutputPath(new FileInfo(inputPath), outputFormat);
                outputPath = PromptText(
                    new TextPrompt<string>("[green]?[/] Output file path:")
                        .DefaultValue(autoOutput));

                password = null;
                passwordFile = null;
                if (outputFormat == FormatType.Pfx)
                {
                    var rawPass = PromptText(
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
                    var rawPass = PromptText(
                        new TextPrompt<string>("[green]?[/] Source PFX password (leave blank if not a PFX):")
                            .AllowEmpty()
                            .Secret());
                    password = string.IsNullOrEmpty(rawPass) ? null : rawPass;
                }

                WriteEquivalentCommand($"certz convert \"{inputPath}\" --to {formatExt} --output \"{outputPath}\"");
            })
            .Run();

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
        var warnDays = 30;
        var quietMode = false;

        new WizardRunner("Certz", "Monitor")
            .AddStep("Sources", () =>
            {
                sources = [];
                SetBackNavigation(false);
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
                SetBackNavigation(true);

                if (sources.Count == 0)
                    throw new OperationCanceledException("No sources specified.");
            })
            .AddStep("Options", () =>
            {
                warnDays = PromptText(
                    new TextPrompt<int>("[green]?[/] Warn when expiring within (days):")
                        .DefaultValue(30)
                        .ValidationErrorMessage("[red]Must be a positive number[/]")
                        .Validate(d => d > 0));

                quietMode = AnsiConsole.Confirm(
                    "[green]?[/] Show only certificates within warning threshold?", defaultValue: false);

                var sourcesArg = string.Join(" ", sources.Select(s => $"\"{s}\""));
                WriteEquivalentCommand($"certz monitor {sourcesArg} --warn {warnDays}{(quietMode ? " --quiet" : "")}");
            })
            .Run();

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

        var source = "";
        string? password = null;
        var days = 90;
        var keepKey = false;
        var outputPath = "";

        new WizardRunner("Certz", "Renew")
            .AddStep("Source Certificate", () =>
            {
                source = PromptCertificateFile(
                    "[green]?[/] Source certificate:",
                    "Enter thumbprint or path manually...",
                    validateExists: false);

                password = null;
                if (File.Exists(source))
                {
                    var rawPass = PromptText(
                        new TextPrompt<string>("[green]?[/] Password (leave blank if none):")
                            .AllowEmpty()
                            .Secret());
                    password = string.IsNullOrEmpty(rawPass) ? null : rawPass;
                }
            })
            .AddStep("Renewal Options", () =>
            {
                days = PromptText(
                    new TextPrompt<int>("[green]?[/] New validity period (days):")
                        .DefaultValue(90)
                        .ValidationErrorMessage("[red]Days must be between 1 and 398[/]")
                        .Validate(d => d >= 1 && d <= 398));

                keepKey = AnsiConsole.Confirm(
                    "[green]?[/] Preserve existing private key (no new key generation)?", defaultValue: false);
            })
            .AddStep("Output", () =>
            {
                var defaultOutput = File.Exists(source)
                    ? Path.Combine(
                        Path.GetDirectoryName(source) ?? ".",
                        Path.GetFileNameWithoutExtension(source) + "-renewed" + Path.GetExtension(source))
                    : source + "-renewed.pfx";

                outputPath = PromptText(
                    new TextPrompt<string>("[green]?[/] Output file path:")
                        .DefaultValue(defaultOutput));

                WriteEquivalentCommand(
                    $"certz renew \"{source}\" --days {days}{(keepKey ? " --keep-key" : "")} --output \"{outputPath}\"");
            })
            .Run();

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
    // Store list wizard
    // =========================================================================

    internal static StoreListOptions RunStoreListWizard()
    {
        WriteWelcome("List Certificates in Store",
            "Browse certificates installed in the Windows certificate store.",
            "You can filter by expiration status.");

        var storeKey = "My";
        var storeLocation = "CurrentUser";
        bool showExpired = false;
        bool validOnly = false;
        int? expiringDays = null;

        new WizardRunner("Certz", "Store", "List")
            .AddStep("Store Selection", () =>
            {
                var storeName = ThrowIfCancelled(AnsiConsole.Prompt(
                    new SelectionPrompt<string>()
                        .Title("[green]?[/] Certificate store:")
                        .AddChoices("My (Personal)", "Root (Trusted Root CAs)", "CA (Intermediate CAs)", "TrustedPeople", "TrustedPublisher", CancelChoice)
                        .HighlightStyle(HighlightStyle)));
                storeKey = storeName.Split(' ')[0];

                storeLocation = ThrowIfCancelled(AnsiConsole.Prompt(
                    new SelectionPrompt<string>()
                        .Title("[green]?[/] Store location:")
                        .AddChoices("CurrentUser", "LocalMachine", CancelChoice)
                        .HighlightStyle(HighlightStyle)));
            })
            .AddStep("Filter", () =>
            {
                var filterChoice = ThrowIfCancelled(AnsiConsole.Prompt(
                    new SelectionPrompt<string>()
                        .Title("[green]?[/] Filter certificates:")
                        .AddChoices("Show all", "Valid only", "Expiring soon (within N days)", "Expired only", CancelChoice)
                        .HighlightStyle(HighlightStyle)));

                showExpired = false;
                validOnly = false;
                expiringDays = null;

                switch (filterChoice)
                {
                    case "Expired only":
                        showExpired = true;
                        break;
                    case "Valid only":
                        validOnly = true;
                        break;
                    case "Expiring soon (within N days)":
                        expiringDays = PromptText(
                            new TextPrompt<int>("[green]?[/] Expiring within how many days:")
                                .DefaultValue(30)
                                .ValidationErrorMessage("[red]Must be a positive number[/]")
                                .Validate(d => d > 0));
                        break;
                }

                var cmd = $"certz store list --store {storeKey} --location {storeLocation}";
                if (showExpired) cmd += " --expired";
                if (validOnly) cmd += " --not-expired";
                if (expiringDays.HasValue) cmd += $" --expiring {expiringDays.Value}";
                WriteEquivalentCommand(cmd);
            })
            .Run();

        return new StoreListOptions
        {
            StoreName = storeKey,
            StoreLocation = storeLocation,
            ShowExpired = showExpired,
            ValidOnly = validOnly,
            ExpiringDays = expiringDays
        };
    }

    // =========================================================================
    // Shared helpers
    // =========================================================================

    private record FileChoice(string Display, string FullPath);

    private static readonly string[] CertificateExtensions =
        { "*.pfx", "*.p12", "*.pem", "*.crt", "*.cer", "*.der", "*.key" };

    private static string PromptCertificateFile(
        string title,
        string manualLabel = "Enter path manually...",
        bool validateExists = true)
    {
        var currentDirectory = Directory.GetCurrentDirectory();
        var certzDirectory = AppContext.BaseDirectory;

        var directories = new[] { currentDirectory, certzDirectory };

        var files = directories
            .SelectMany(dir => CertificateExtensions
                .SelectMany(ext => Directory.EnumerateFiles(dir, ext)))
            .Select(fullPath =>
            {
                string label;
                // Determine which "root" this file belongs to for the label
                if (fullPath.StartsWith(certzDirectory, StringComparison.OrdinalIgnoreCase))
                    label = "[certz path]";
                else if (fullPath.StartsWith(currentDirectory, StringComparison.OrdinalIgnoreCase))
                    label = "[.]";
                else
                    label = "[external]";

                return new FileChoice(
                    $"{label.EscapeMarkup()} {Path.GetRelativePath(Directory.GetCurrentDirectory(), fullPath)}",
                    fullPath);
            })
            .DistinctBy(x => x.FullPath)
            .ToList();

        if (files.Count > 0)
        {
            files.Add(new FileChoice($"[[manual]] {manualLabel}", ""));
            files.Add(new FileChoice(CancelChoice, CancelChoice));
            var choice = AnsiConsole.Prompt(
                new SelectionPrompt<FileChoice>()
                    .Title(title)
                    .AddChoices(files)
                    .UseConverter(f => f.Display)
                    .HighlightStyle(HighlightStyle));

            ThrowIfCancelled(choice.FullPath);

            if (!string.IsNullOrEmpty(choice.FullPath))
                return choice.FullPath;
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

    internal static string BuildDevCommandLine(DevCertificateOptions options)
    {
        var sb = new StringBuilder("certz create dev");
        sb.Append($" \"{options.Domain}\"");

        foreach (var san in options.AdditionalSANs)
            sb.Append($" --san \"{san}\"");

        sb.Append($" --days {options.Days}");
        sb.Append($" --key-type {options.KeyType}");

        if (options.KeyType.StartsWith("RSA", StringComparison.OrdinalIgnoreCase))
            sb.Append($" --key-size {options.KeySize}");

        if (options.PfxFile != null)
            sb.Append($" --file \"{options.PfxFile.Name}\"");
        if (options.CertFile != null)
            sb.Append($" --cert \"{options.CertFile.Name}\"");
        if (options.KeyFile != null)
            sb.Append($" --key \"{options.KeyFile.Name}\"");

        if (options.Trust)
        {
            sb.Append(" --trust");
            if (options.TrustLocation != StoreLocation.CurrentUser)
                sb.Append($" --trust-location {options.TrustLocation}");
        }

        if (options.PasswordFile != null)
            sb.Append($" --password-file \"{options.PasswordFile.Name}\"");

        return sb.ToString();
    }

    internal static string BuildCaCommandLine(CACertificateOptions options)
    {
        var sb = new StringBuilder("certz create ca");
        sb.Append($" --name \"{options.Name}\"");
        sb.Append($" --days {options.Days}");
        sb.Append($" --key-type {options.KeyType}");

        if (options.KeyType.StartsWith("RSA", StringComparison.OrdinalIgnoreCase))
            sb.Append($" --key-size {options.KeySize}");

        if (options.PathLength >= 0)
            sb.Append($" --path-length {options.PathLength}");

        if (options.PfxFile != null)
            sb.Append($" --file \"{options.PfxFile.Name}\"");
        if (options.CertFile != null)
            sb.Append($" --cert \"{options.CertFile.Name}\"");
        if (options.KeyFile != null)
            sb.Append($" --key \"{options.KeyFile.Name}\"");

        if (options.Trust)
        {
            sb.Append(" --trust");
            if (options.TrustLocation != StoreLocation.CurrentUser)
                sb.Append($" --trust-location {options.TrustLocation}");
        }

        if (options.PasswordFile != null)
            sb.Append($" --password-file \"{options.PasswordFile.Name}\"");

        return sb.ToString();
    }

    internal static void WriteEquivalentCommand(string command)
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

    // =========================================================================
    // Store browser helpers (Phase 11)
    // =========================================================================

    private record StoreCertificateChoice(string Display, string Thumbprint, string Subject, string StatusColor = "green");

    private static string BrowseOrEnterThumbprint(string storeName, string storeLocation)
    {
        var findMethod = ThrowIfCancelled(AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title("[green]?[/] How would you like to find the certificate?")
                .AddChoices(
                    "Browse certificates in store",
                    "Search by subject (supports wildcards)",
                    "Enter thumbprint manually",
                    CancelChoice)
                .HighlightStyle(HighlightStyle)));

        return findMethod switch
        {
            "Browse certificates in store" => BrowseStore(storeName, storeLocation, subjectFilter: null),
            "Search by subject (supports wildcards)" => SearchBySubject(storeName, storeLocation),
            _ => PromptThumbprintManually()
        };
    }

    private static string BrowseStore(string storeName, string storeLocation, string? subjectFilter)
    {
        bool showExpired = false;
        int? expiringDays = null;
        bool validOnly = false;

        if (subjectFilter == null)
        {
            var filterChoice = ThrowIfCancelled(AnsiConsole.Prompt(
                new SelectionPrompt<string>()
                    .Title("[green]?[/] Filter certificates:")
                    .AddChoices("Show all", "Valid only", "Expiring soon (within N days)", "Expired only", CancelChoice)
                    .HighlightStyle(HighlightStyle)));

            switch (filterChoice)
            {
                case "Expired only":
                    showExpired = true;
                    break;
                case "Expiring soon (within N days)":
                    expiringDays = AnsiConsole.Prompt(
                        new TextPrompt<int>("[green]?[/] Expiring within how many days:")
                            .DefaultValue(30)
                            .ValidationErrorMessage("[red]Must be a positive number[/]")
                            .Validate(d => d > 0));
                    break;
                case "Valid only":
                    validOnly = true;
                    break;
            }
        }

        var listOptions = new StoreListOptions
        {
            StoreName = storeName,
            StoreLocation = storeLocation,
            ShowExpired = showExpired,
            ValidOnly = validOnly,
            ExpiringDays = expiringDays
        };

        var result = StoreListHandler.ListCertificates(listOptions);

        // Apply additional filters
        var certs = result.Certificates;

        if (!string.IsNullOrEmpty(subjectFilter) && subjectFilter != "*")
        {
            var pattern = "^" + Regex.Escape(subjectFilter)
                .Replace("\\*", ".*")
                .Replace("\\?", ".") + "$";
            var regex = new Regex(pattern, RegexOptions.IgnoreCase);
            certs = certs.Where(c => regex.IsMatch(c.Subject)).ToList();
        }

        if (certs.Count == 0)
        {
            AnsiConsole.MarkupLine("[yellow]  No certificates found matching the filter.[/]");
            return PromptThumbprintManually();
        }

        AnsiConsole.MarkupLine($"[grey]  Found {certs.Count} certificate(s) (of {result.TotalCount} total).[/]");

        // Calculate column widths for aligned display
        var maxCnLen = certs.Max(c => ExtractCN(c.Subject).Length);
        // Status text lengths vary: "Expired" (7), "Expiring (Nd)" (13-15), "Valid" (5)
        var maxStatusLen = certs.Max(c => c.IsExpired ? 7
            : c.DaysRemaining <= 30 ? $"Expiring ({c.DaysRemaining}d)".Length
            : 5);

        var choices = certs.Select(c =>
        {
            var cn = ExtractCN(c.Subject).PadRight(maxCnLen);
            var thumbShort = c.Thumbprint[..8];
            var statusText = c.IsExpired
                ? "Expired"
                : c.DaysRemaining <= 30
                    ? $"Expiring ({c.DaysRemaining}d)"
                    : "Valid";
            var statusColor = c.IsExpired ? "red"
                : c.DaysRemaining <= 30 ? "yellow"
                : "green";
            // Entire row colored by status; HighlightStyle (cyan) overrides on the selected row
            var display = $"[{statusColor}]{cn}  {thumbShort}...  {c.NotAfter:yyyy-MM-dd}  {statusText.PadRight(maxStatusLen)}[/]";
            return new StoreCertificateChoice(display, c.Thumbprint, c.Subject, statusColor);
        }).ToList();

        choices.Add(new StoreCertificateChoice(CancelChoice, CancelChoice, "", "grey"));

        var selected = AnsiConsole.Prompt(
            new SelectionPrompt<StoreCertificateChoice>()
                .Title("[green]?[/] Select a certificate:")
                .AddChoices(choices)
                .UseConverter(c => c.Display)
                .HighlightStyle(new Style(Color.Cyan1)));

        ThrowIfCancelled(selected.Thumbprint);

        // Show full thumbprint for easy copying
        AnsiConsole.MarkupLine($"[grey]  Selected: {Markup.Escape(selected.Subject)}[/]");
        AnsiConsole.MarkupLine($"[cyan]  Thumbprint: {selected.Thumbprint}[/]");

        return selected.Thumbprint;
    }

    private static string SearchBySubject(string storeName, string storeLocation)
    {
        var filter = AnsiConsole.Prompt(
            new TextPrompt<string>("[green]?[/] Subject filter (use * for wildcard, e.g. *localhost*):")
                .Validate(f => !string.IsNullOrWhiteSpace(f)
                    ? ValidationResult.Success()
                    : ValidationResult.Error("[red]Filter cannot be empty[/]")));

        return BrowseStore(storeName, storeLocation, subjectFilter: filter);
    }

    private static string PromptThumbprintManually()
    {
        return AnsiConsole.Prompt(
            new TextPrompt<string>("[green]?[/] Certificate thumbprint (full 40-char or partial 8+):")
                .WithConverter(input => AlphaNumericRegex().Replace(input, ""))
                .Validate(t => !string.IsNullOrWhiteSpace(t) && t.Length >= 8
                    ? ValidationResult.Success()
                    : ValidationResult.Error("[red]Thumbprint must be at least 8 hex characters[/]")));
    }

    private static string ExtractCN(string subject)
    {
        var match = Regex.Match(subject, @"CN=([^,]+)");
        return match.Success ? match.Groups[1].Value.Trim() : subject;
    }

    // =========================================================================
    // Trust remove display + export helpers (Phase 11)
    // =========================================================================

    private static void DisplayMatchedCertificates(List<X509Certificate2> certificates)
    {
        foreach (var cert in certificates)
        {
            var isSelfSigned = string.Equals(cert.Subject, cert.Issuer, StringComparison.Ordinal);
            var basicConstraints = cert.Extensions["2.5.29.19"] as X509BasicConstraintsExtension;
            var isCa = basicConstraints?.CertificateAuthority ?? false;
            var isExpired = cert.NotAfter < DateTime.Now;

            var table = new Table()
                .Border(TableBorder.Rounded)
                .BorderColor(Color.Grey)
                .AddColumn(new TableColumn("[bold]Property[/]").Width(16))
                .AddColumn(new TableColumn("[bold]Value[/]"));

            table.AddRow("Subject", Markup.Escape(cert.Subject));
            table.AddRow("Issuer", Markup.Escape(cert.Issuer));
            table.AddRow("Thumbprint", $"[cyan]{cert.Thumbprint}[/]");
            table.AddRow("Not Before", cert.NotBefore.ToString("yyyy-MM-dd"));
            table.AddRow("Not After", cert.NotAfter.ToString("yyyy-MM-dd"));
            table.AddRow("Is CA", isCa ? "[yellow]Yes[/]" : "No");
            table.AddRow("Self-Signed", isSelfSigned ? "[yellow]Yes[/]" : "No");
            table.AddRow("Has Key", cert.HasPrivateKey ? "Yes" : "No");
            table.AddRow("Status", isExpired ? "[red]Expired[/]" : "[green]Valid[/]");

            AnsiConsole.Write(table);
        }
    }

    private static void SaveRemovalSummary(List<X509Certificate2> certificates, string storeName, string storeLocation)
    {
        var defaultPath = $"removed-certs-{DateTimeOffset.UtcNow:yyyy-MM-dd}.txt";
        var path = AnsiConsole.Prompt(
            new TextPrompt<string>("[green]?[/] Output file path:")
                .DefaultValue(defaultPath));

        var sb = new StringBuilder();
        sb.AppendLine("Certificate Removal Summary");
        sb.AppendLine($"Generated: {DateTimeOffset.UtcNow:yyyy-MM-dd HH:mm:ss} UTC");
        sb.AppendLine($"Store: {storeLocation}\\{storeName}");
        sb.AppendLine();

        for (var i = 0; i < certificates.Count; i++)
        {
            var cert = certificates[i];
            var basicConstraints = cert.Extensions["2.5.29.19"] as X509BasicConstraintsExtension;
            var isCa = basicConstraints?.CertificateAuthority ?? false;
            var isSelfSigned = string.Equals(cert.Subject, cert.Issuer, StringComparison.Ordinal);
            var isExpired = cert.NotAfter < DateTime.Now;

            sb.AppendLine($"Certificate #{i + 1}:");
            sb.AppendLine($"  Subject:     {cert.Subject}");
            sb.AppendLine($"  Issuer:      {cert.Issuer}");
            sb.AppendLine($"  Thumbprint:  {cert.Thumbprint}");
            sb.AppendLine($"  Not Before:  {cert.NotBefore:yyyy-MM-dd}");
            sb.AppendLine($"  Not After:   {cert.NotAfter:yyyy-MM-dd}");
            sb.AppendLine($"  Is CA:       {(isCa ? "Yes" : "No")}");
            sb.AppendLine($"  Self-Signed: {(isSelfSigned ? "Yes" : "No")}");
            sb.AppendLine($"  Has Key:     {(cert.HasPrivateKey ? "Yes" : "No")}");
            sb.AppendLine($"  Status:      {(isExpired ? "Expired" : "Valid")}");
            sb.AppendLine();
        }

        File.WriteAllText(path, sb.ToString());
        AnsiConsole.MarkupLine($"[green]  Saved certificate details to {Markup.Escape(path)}[/]");
    }

    // =========================================================================
    // URL normalization helpers (Phase 11)
    // =========================================================================

    private static (string Url, string? Warning) NormalizeUrl(string input)
    {
        input = input.Trim();

        // Already has https://
        if (input.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            return (input, null);

        // Has http:// — check if CRL endpoint
        if (input.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
        {
            if (Uri.TryCreate(input, UriKind.Absolute, out var uri))
            {
                var isCrl = uri.AbsolutePath.EndsWith(".crl", StringComparison.OrdinalIgnoreCase)
                            || uri.Host.StartsWith("crl.", StringComparison.OrdinalIgnoreCase);

                if (isCrl)
                    return (input, "CRL endpoint uses non-secure HTTP. Proceeding with caution.");
            }

            // Non-CRL http:// — upgrade to https://
            var upgraded = "https://" + input[7..];
            return (upgraded, "Non-secure URL detected. Upgrading to HTTPS.");
        }

        // No protocol — prepend https://
        return ("https://" + input, null);
    }

    private static string PromptUrl(string title = "[green]?[/] URL (e.g. example.com or https://example.com):")
    {
        var raw = AnsiConsole.Prompt(
            new TextPrompt<string>(title)
                .Validate(u => !string.IsNullOrWhiteSpace(u)
                    ? ValidationResult.Success()
                    : ValidationResult.Error("[red]URL cannot be empty[/]")));

        var (url, warning) = NormalizeUrl(raw);

        if (warning != null)
            AnsiConsole.MarkupLine($"[yellow]  {warning}[/]");

        if (!string.Equals(url, raw, StringComparison.Ordinal))
            AnsiConsole.MarkupLine($"[grey]  Using: {Markup.Escape(url)}[/]");

        return url;
    }

    [GeneratedRegex(@"[^0-9a-fA-F]+$")]
    private static partial Regex AlphaNumericRegex();

    // =========================================================================
    // Step-based wizard runner with breadcrumb and back navigation
    // =========================================================================

    /// <summary>
    /// Runs a sequence of wizard steps with breadcrumb display, keyboard tips,
    /// and left-arrow back navigation support.
    /// </summary>
    private sealed class WizardRunner
    {
        private record Step(string Label, Action Execute);

        private readonly string[] _path;
        private readonly List<Step> _steps = [];

        /// <param name="breadcrumbPath">
        /// Segments for the breadcrumb trail, e.g. ("Certz", "Create", "Dev Certificate").
        /// </param>
        public WizardRunner(params string[] breadcrumbPath) => _path = breadcrumbPath;

        public WizardRunner AddStep(string label, Action execute)
        {
            _steps.Add(new Step(label, execute));
            return this;
        }

        public void Run()
        {
            int current = 0;
            while (current < _steps.Count)
            {
                var step = _steps[current];
                AnsiConsole.WriteLine();
                WriteBreadcrumb(_path, current + 1, _steps.Count, step.Label);
                WriteTips(canGoBack: current > 0);

                try
                {
                    step.Execute();
                    current++;
                }
                catch (WizardBackException)
                {
                    if (current > 0) current--;
                    // At step 0, re-render the same step
                }
            }
        }
    }

    private static void WriteBreadcrumb(string[] path, int step, int totalSteps, string stepLabel)
    {
        var segments = path.Select(s => $"[blue]{Markup.Escape(s)}[/]").ToList();
        segments.Add($"[bold]Step {step}/{totalSteps}: {Markup.Escape(stepLabel)}[/]");
        var trail = string.Join($" [grey]>[/] ", segments);
        AnsiConsole.MarkupLine(trail);
    }

    private static void WriteTips(bool canGoBack)
    {
        var tips = canGoBack
            ? "[grey]Enter Select  \u2190 Back  Esc Cancel[/]"
            : "[grey]Enter Select  Esc Cancel[/]";
        AnsiConsole.MarkupLine($"  {tips}");
        AnsiConsole.WriteLine();
    }

    // =========================================================================
    // Escape key cancellation support
    // =========================================================================

    /// <summary>
    /// Wraps an IAnsiConsole to intercept the Escape key during prompts,
    /// triggering cancellation via OperationCanceledException.
    /// </summary>
    private sealed class EscapeCancellableConsole(IAnsiConsole inner, EscapeCancellableInput escapableInput) : IAnsiConsole
    {
        public Profile Profile => inner.Profile;
        public IAnsiConsoleCursor Cursor => inner.Cursor;
        public IAnsiConsoleInput Input { get; } = escapableInput;
        public IExclusivityMode ExclusivityMode => inner.ExclusivityMode;
        public RenderPipeline Pipeline => inner.Pipeline;

        public void Clear(bool home) => inner.Clear(home);
        public void Write(IRenderable renderable) => inner.Write(renderable);
    }

    /// <summary>
    /// Intercepts keyboard input: Escape throws OperationCanceledException,
    /// Left arrow throws WizardBackException (when BackNavigationEnabled is true).
    /// </summary>
    private sealed class EscapeCancellableInput(IAnsiConsoleInput originalInput) : IAnsiConsoleInput
    {
        /// <summary>
        /// When true, pressing Left arrow throws WizardBackException.
        /// Disabled during TextPrompt input so Left arrow moves the cursor.
        /// </summary>
        public bool BackNavigationEnabled { get; set; } = true;

        public bool IsKeyAvailable() => originalInput.IsKeyAvailable();

        public ConsoleKeyInfo? ReadKey(bool intercept)
        {
            var key = originalInput.ReadKey(intercept);
            if (key?.Key == ConsoleKey.Escape)
                throw new OperationCanceledException("Cancelled by Escape key");
            if (BackNavigationEnabled && key?.Key == ConsoleKey.LeftArrow)
                throw new WizardBackException();
            return key;
        }

        public async Task<ConsoleKeyInfo?> ReadKeyAsync(bool intercept, CancellationToken cancellationToken)
        {
            var key = await originalInput.ReadKeyAsync(intercept, cancellationToken);
            if (key?.Key == ConsoleKey.Escape)
                throw new OperationCanceledException("Cancelled by Escape key");
            if (BackNavigationEnabled && key?.Key == ConsoleKey.LeftArrow)
                throw new WizardBackException();
            return key;
        }
    }
}
