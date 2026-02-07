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
        if (!generatePassword)
        {
            password = AnsiConsole.Prompt(
                new TextPrompt<string>("[green]?[/] Enter password:")
                    .Secret()
                    .ValidationErrorMessage("[red]Password cannot be empty[/]")
                    .Validate(p => !string.IsNullOrWhiteSpace(p)));
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
            Password = password
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
        if (!generatePassword)
        {
            password = AnsiConsole.Prompt(
                new TextPrompt<string>("[green]?[/] Enter password:")
                    .Secret()
                    .ValidationErrorMessage("[red]Password cannot be empty[/]")
                    .Validate(p => !string.IsNullOrWhiteSpace(p)));
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
            Password = password
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
}
