using certz.Models;
using certz.Options;
using Spectre.Console;

namespace certz.Services;

internal static class CertificateWizard
{
    internal static DevCertificateOptions RunDevCertificateWizard()
    {
        AnsiConsole.Write(new Rule("[bold blue]Development Certificate Wizard[/]").RuleStyle("blue"));
        AnsiConsole.WriteLine();

        // Domain name
        var domain = AnsiConsole.Prompt(
            new TextPrompt<string>("Enter the [green]primary domain[/] name:")
                .DefaultValue("localhost")
                .ValidationErrorMessage("[red]Domain name cannot be empty[/]")
                .Validate(d => !string.IsNullOrWhiteSpace(d)));

        // Additional SANs
        var addSans = AnsiConsole.Confirm("Add additional [green]Subject Alternative Names (SANs)[/]?", defaultValue: false);
        var additionalSans = new List<string>();
        if (addSans)
        {
            AnsiConsole.MarkupLine("[grey]Enter SANs one per line. Press Enter on empty line when done.[/]");
            while (true)
            {
                var san = AnsiConsole.Prompt(
                    new TextPrompt<string>("[grey]SAN:[/]")
                        .AllowEmpty());
                if (string.IsNullOrWhiteSpace(san)) break;
                additionalSans.Add(san);
            }
        }

        // Validity period
        var days = AnsiConsole.Prompt(
            new TextPrompt<int>("Certificate validity in [green]days[/]:")
                .DefaultValue(90)
                .ValidationErrorMessage("[red]Days must be between 1 and 398[/]")
                .Validate(d => d >= 1 && d <= 398));

        // Key type
        var keyType = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title("Select [green]key type[/]:")
                .AddChoices(OptionBuilders.validKeyTypes)
                .HighlightStyle(new Style(Color.Green)));

        // Key size (only for RSA)
        var keySize = 3072;
        if (keyType == "RSA")
        {
            keySize = AnsiConsole.Prompt(
                new SelectionPrompt<int>()
                    .Title("Select [green]RSA key size[/]:")
                    .AddChoices(2048, 3072, 4096)
                    .HighlightStyle(new Style(Color.Green)));
        }

        // Trust
        var trust = AnsiConsole.Confirm("Install to [green]trusted root store[/]?", defaultValue: false);

        // Output file
        var pfxPath = AnsiConsole.Prompt(
            new TextPrompt<string>("Output [green]PFX file path[/]:")
                .DefaultValue($"{domain.Replace("*", "wildcard").Replace(".", "-")}.pfx"));

        // Password
        var generatePassword = AnsiConsole.Confirm("Auto-generate [green]secure password[/]?", defaultValue: true);
        string? password = null;
        if (!generatePassword)
        {
            password = AnsiConsole.Prompt(
                new TextPrompt<string>("Enter [green]password[/]:")
                    .Secret()
                    .ValidationErrorMessage("[red]Password cannot be empty[/]")
                    .Validate(p => !string.IsNullOrWhiteSpace(p)));
        }

        AnsiConsole.WriteLine();
        AnsiConsole.Write(new Rule("[bold green]Configuration Complete[/]").RuleStyle("green"));

        return new DevCertificateOptions
        {
            Domain = domain,
            AdditionalSANs = additionalSans.ToArray(),
            Days = days,
            KeyType = keyType,
            KeySize = keySize,
            Trust = trust,
            PfxFile = new FileInfo(pfxPath),
            Password = password
        };
    }

    internal static CACertificateOptions RunCACertificateWizard()
    {
        AnsiConsole.Write(new Rule("[bold blue]Certificate Authority Wizard[/]").RuleStyle("blue"));
        AnsiConsole.WriteLine();

        // CA Name
        var name = AnsiConsole.Prompt(
            new TextPrompt<string>("Enter the [green]CA name[/] (Common Name):")
                .DefaultValue("Development Root CA")
                .ValidationErrorMessage("[red]CA name cannot be empty[/]")
                .Validate(n => !string.IsNullOrWhiteSpace(n)));

        // Validity period (CAs can have longer validity)
        var days = AnsiConsole.Prompt(
            new TextPrompt<int>("Certificate validity in [green]days[/]:")
                .DefaultValue(3650)
                .ValidationErrorMessage("[red]Days must be at least 1[/]")
                .Validate(d => d >= 1));

        // Path length constraint
        var hasPathLength = AnsiConsole.Confirm("Set [green]path length constraint[/]?", defaultValue: false);
        var pathLength = -1;
        if (hasPathLength)
        {
            pathLength = AnsiConsole.Prompt(
                new TextPrompt<int>("Enter [green]path length[/] (0 = no intermediate CAs, 1 = one level, etc.):")
                    .DefaultValue(0)
                    .ValidationErrorMessage("[red]Path length must be 0 or greater[/]")
                    .Validate(p => p >= 0));
        }

        // Key type
        var keyType = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title("Select [green]key type[/]:")
                .AddChoices(OptionBuilders.validKeyTypes)
                .HighlightStyle(new Style(Color.Green)));

        // Key size (only for RSA)
        var keySize = 3072;
        if (keyType == "RSA")
        {
            keySize = AnsiConsole.Prompt(
                new SelectionPrompt<int>()
                    .Title("Select [green]RSA key size[/]:")
                    .AddChoices(2048, 3072, 4096)
                    .HighlightStyle(new Style(Color.Green)));
        }

        // Trust
        var trust = AnsiConsole.Confirm("Install to [green]trusted root store[/]?", defaultValue: true);

        // Output file
        var pfxPath = AnsiConsole.Prompt(
            new TextPrompt<string>("Output [green]PFX file path[/]:")
                .DefaultValue($"{name.Replace(" ", "-").ToLowerInvariant()}.pfx"));

        // Password
        var generatePassword = AnsiConsole.Confirm("Auto-generate [green]secure password[/]?", defaultValue: true);
        string? password = null;
        if (!generatePassword)
        {
            password = AnsiConsole.Prompt(
                new TextPrompt<string>("Enter [green]password[/]:")
                    .Secret()
                    .ValidationErrorMessage("[red]Password cannot be empty[/]")
                    .Validate(p => !string.IsNullOrWhiteSpace(p)));
        }

        AnsiConsole.WriteLine();
        AnsiConsole.Write(new Rule("[bold green]Configuration Complete[/]").RuleStyle("green"));

        return new CACertificateOptions
        {
            Name = name,
            Days = days,
            PathLength = pathLength,
            KeyType = keyType,
            KeySize = keySize,
            Trust = trust,
            PfxFile = new FileInfo(pfxPath),
            Password = password
        };
    }
}
