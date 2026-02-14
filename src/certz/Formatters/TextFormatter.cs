using certz.Examples;
using certz.Models;
using certz.Services.Validation;
using Spectre.Console;

namespace certz.Formatters;

internal class TextFormatter : IOutputFormatter
{
    public void WriteCertificateCreated(CertificateCreationResult result)
    {
        var table = new Table()
            .Border(TableBorder.Rounded)
            .AddColumn(new TableColumn("[bold]Property[/]").NoWrap())
            .AddColumn(new TableColumn("[bold]Value[/]"));

        table.AddRow("[green]Subject[/]", result.Subject);
        table.AddRow("[green]Thumbprint[/]", result.Thumbprint);
        table.AddRow("[green]Valid From[/]", result.NotBefore.ToUniversalTime().ToString("yyyy-MM-dd") + " UTC");
        table.AddRow("[green]Valid Until[/]", result.NotAfter.ToUniversalTime().ToString("yyyy-MM-dd") + " UTC");
        table.AddRow("[green]Key Type[/]", result.KeyType);

        if (result.SANs.Length > 0)
        {
            table.AddRow("[green]SANs[/]", string.Join(", ", result.SANs));
        }

        if (result.IsCA)
        {
            table.AddRow("[green]Type[/]", "Certificate Authority");
            if (result.PathLength >= 0)
            {
                table.AddRow("[green]Path Length[/]", result.PathLength.ToString());
            }
        }

        AnsiConsole.Write(new Panel(table)
            .Header("[bold green]Certificate Created Successfully[/]")
            .Border(BoxBorder.Rounded));

        // Ephemeral mode warning
        if (result.IsEphemeral)
        {
            AnsiConsole.WriteLine();
            var warningPanel = new Panel(
                new Rows(
                    new Markup("[bold yellow]EPHEMERAL MODE[/]"),
                    new Markup(""),
                    new Markup("Certificate exists in memory only."),
                    new Markup("No files were written to disk."),
                    new Markup("[dim]Certificate will be discarded when this command exits.[/]")
                ))
                .Border(BoxBorder.Double)
                .BorderColor(Color.Yellow);
            AnsiConsole.Write(warningPanel);
        }
        else if (result.WasPiped)
        {
            // Pipe mode - minimal output, content went to stdout
            // Don't display file list since there are none
        }
        else if (result.OutputFiles.Length > 0)
        {
            // Output files section (normal mode)
            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine("[bold]Saved Files:[/]");
            foreach (var file in result.OutputFiles)
            {
                AnsiConsole.MarkupLine($"  [blue]-[/] {Markup.Escape(file)}");
            }
        }

        // Password warning if generated (not in ephemeral/pipe mode)
        if (!result.IsEphemeral && !result.WasPiped &&
            result.PasswordWasGenerated && !string.IsNullOrEmpty(result.Password))
        {
            AnsiConsole.WriteLine();
            var passwordPanel = new Panel(
                new Rows(
                    new Markup($"[bold cyan]{Markup.Escape(result.Password)}[/]"),
                    new Markup(""),
                    new Markup("[yellow]Store this password securely! This is your only chance to see it.[/]")
                ))
                .Header("[bold yellow]Generated Password[/]")
                .Border(BoxBorder.Double)
                .BorderColor(Color.Yellow);
            AnsiConsole.Write(passwordPanel);
        }

        // Trust notification
        if (result.WasTrusted)
        {
            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine("[green]Certificate installed to CurrentUser\\Root trust store.[/]");
        }
    }

    public void WriteCertificateInspected(CertificateInspectResult result)
    {
        var table = new Table()
            .Border(TableBorder.Rounded)
            .AddColumn(new TableColumn("[bold]Property[/]").NoWrap())
            .AddColumn(new TableColumn("[bold]Value[/]"));

        table.AddRow("[green]Subject[/]", Markup.Escape(result.Subject));
        table.AddRow("[green]Issuer[/]", Markup.Escape(result.Issuer));
        table.AddRow("[green]Thumbprint[/]", result.Thumbprint);
        table.AddRow("[green]Serial Number[/]", result.SerialNumber);
        table.AddRow("[green]Valid From[/]", result.NotBefore.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss") + " UTC");
        table.AddRow("[green]Valid To[/]", result.NotAfter.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss") + " UTC");

        // Days remaining with color coding
        var daysColor = result.DaysRemaining switch
        {
            < 0 => "red",
            < 30 => "yellow",
            _ => "green"
        };
        table.AddRow("[green]Days Remaining[/]", $"[{daysColor}]{result.DaysRemaining}[/]");

        table.AddRow("[green]Key Algorithm[/]", $"{result.KeyAlgorithm} ({result.KeySize} bits)");
        table.AddRow("[green]Signature Algorithm[/]", result.SignatureAlgorithm);
        table.AddRow("[green]Is CA[/]", result.IsCa ? "[cyan]Yes[/]" : "No");

        if (result.IsCa && result.PathLengthConstraint.HasValue)
        {
            table.AddRow("[green]Path Length[/]", result.PathLengthConstraint.Value.ToString());
        }

        table.AddRow("[green]Has Private Key[/]", result.HasPrivateKey ? "[cyan]Yes[/]" : "No");

        if (result.SubjectAlternativeNames.Count > 0)
        {
            table.AddRow("[green]SANs[/]", string.Join("\n", result.SubjectAlternativeNames.Select(Markup.Escape)));
        }

        if (result.KeyUsages.Count > 0)
        {
            table.AddRow("[green]Key Usage[/]", string.Join(", ", result.KeyUsages));
        }

        if (result.EnhancedKeyUsages.Count > 0)
        {
            table.AddRow("[green]Enhanced Key Usage[/]", string.Join(", ", result.EnhancedKeyUsages));
        }

        table.AddRow("[green]Source[/]", $"{result.Source}: {Markup.Escape(result.SourcePath ?? "")}");

        var header = result.Warnings.Count == 0
            ? "[bold green]Certificate Details[/]"
            : "[bold yellow]Certificate Details[/]";

        AnsiConsole.Write(new Panel(table)
            .Header(header)
            .Border(BoxBorder.Rounded));

        // Show warnings
        if (result.Warnings.Count > 0)
        {
            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine("[bold yellow]Warnings:[/]");
            foreach (var warning in result.Warnings)
            {
                AnsiConsole.MarkupLine($"  [yellow]-[/] {Markup.Escape(warning)}");
            }
        }

        // Show chain if present
        if (result.Chain != null && result.Chain.Count > 0)
        {
            AnsiConsole.WriteLine();
            if (result.DetailedTree)
            {
                var visualizer = new ChainVisualizer();
                visualizer.RenderDetailedChain(result.Chain, result.ChainIsValid, AnsiConsole.Console);
            }
            else
            {
                RenderChainFromInfo(result.Chain, result.ChainIsValid);
            }
        }
    }

    /// <summary>
    /// Renders a certificate chain using ChainElementInfo (serializable chain data).
    /// </summary>
    private static void RenderChainFromInfo(List<ChainElementInfo> chain, bool isValid)
    {
        var root = new Tree("[bold]Certificate Chain[/]");

        // Build tree from root CA down to end entity
        // Chain is ordered from end-entity (index 0) to root CA (last index)
        TreeNode? currentNode = null;
        for (int i = chain.Count - 1; i >= 0; i--)
        {
            var element = chain[i];
            var nodeText = BuildChainNodeText(element, i == 0);

            if (currentNode == null)
            {
                currentNode = root.AddNode(nodeText);
            }
            else
            {
                currentNode = currentNode.AddNode(nodeText);
            }
        }

        AnsiConsole.Write(root);

        // Show overall chain status
        if (!isValid)
        {
            AnsiConsole.MarkupLine("");
            AnsiConsole.MarkupLine("[red]Chain validation failed[/]");
        }
        else
        {
            AnsiConsole.MarkupLine("");
            AnsiConsole.MarkupLine("[green]Chain validation successful[/]");
        }
    }

    /// <summary>
    /// Builds the display text for a chain element node.
    /// </summary>
    private static string BuildChainNodeText(ChainElementInfo element, bool isEndEntity)
    {
        var sb = new System.Text.StringBuilder();

        // Certificate type indicator
        string typeLabel;
        if (isEndEntity)
        {
            typeLabel = "[blue]End Entity[/]";
        }
        else if (element.IsCa)
        {
            typeLabel = element.IsSelfSigned ? "[green]Root CA[/]" : "[cyan]Intermediate CA[/]";
        }
        else
        {
            typeLabel = "[grey]Certificate[/]";
        }

        // Subject name - extract CN from the subject
        var subject = element.Subject;
        if (subject.Contains("CN="))
        {
            var cnStart = subject.IndexOf("CN=") + 3;
            var cnEnd = subject.IndexOf(',', cnStart);
            subject = cnEnd > 0 ? subject.Substring(cnStart, cnEnd - cnStart) : subject.Substring(cnStart);
        }
        sb.Append($"{typeLabel}: [bold]{Markup.Escape(subject)}[/]");

        // Validity indicator
        var now = DateTime.Now;
        if (element.NotAfter < now)
        {
            sb.Append(" [red](EXPIRED)[/]");
        }
        else if (element.NotBefore > now)
        {
            sb.Append(" [yellow](NOT YET VALID)[/]");
        }
        else
        {
            var daysRemaining = (element.NotAfter - now).Days;
            if (daysRemaining < 30)
            {
                sb.Append($" [yellow]({daysRemaining} days remaining)[/]");
            }
        }

        // Thumbprint (abbreviated for display)
        sb.Append($"\n  Thumbprint: [dim]{element.Thumbprint[..Math.Min(16, element.Thumbprint.Length)]}...[/]");

        // Expiration date
        sb.Append($"\n  Expires: [dim]{element.NotAfter.ToUniversalTime():yyyy-MM-dd} UTC[/]");

        // Validation errors
        foreach (var error in element.ValidationErrors)
        {
            sb.Append($"\n  [red]- {Markup.Escape(error)}[/]");
        }

        return sb.ToString();
    }

    public void WriteStoreList(StoreListResult result)
    {
        var table = new Table()
            .Border(TableBorder.Rounded)
            .AddColumn(new TableColumn("[bold]Subject[/]"))
            .AddColumn(new TableColumn("[bold]Thumbprint[/]").NoWrap())
            .AddColumn(new TableColumn("[bold]Expires (UTC)[/]").NoWrap())
            .AddColumn(new TableColumn("[bold]Days[/]").Centered())
            .AddColumn(new TableColumn("[bold]Key[/]").Centered())
            .AddColumn(new TableColumn("[bold]CA[/]").Centered());

        foreach (var cert in result.Certificates)
        {
            // Color code expiration
            var daysColor = cert.DaysRemaining switch
            {
                < 0 => "red",
                < 30 => "yellow",
                _ => "green"
            };

            // Extract CN from subject
            var subject = GetSimpleName(cert.Subject);

            table.AddRow(
                Markup.Escape(subject.Length > 40 ? subject[..37] + "..." : subject),
                $"[dim]{cert.Thumbprint[..16]}...[/]",
                cert.NotAfter.ToUniversalTime().ToString("yyyy-MM-dd"),
                $"[{daysColor}]{cert.DaysRemaining}[/]",
                cert.HasPrivateKey ? "[cyan]Yes[/]" : "[dim]No[/]",
                cert.IsCa ? "[cyan]Yes[/]" : "[dim]No[/]"
            );
        }

        var headerText = $"[bold]{result.StoreLocation}\\{result.StoreName}[/] ({result.FilteredCount} of {result.TotalCount} certificates)";
        AnsiConsole.Write(new Panel(table)
            .Header(headerText)
            .Border(BoxBorder.Rounded));
    }

    public void WriteTrustAdded(TrustOperationResult result)
    {
        if (!result.Success)
        {
            WriteError(result.ErrorMessage ?? "Unknown error");
            return;
        }

        foreach (var cert in result.Certificates)
        {
            var subject = GetSimpleName(cert.Subject);
            AnsiConsole.MarkupLine($"[green]Certificate added to {result.StoreLocation}\\{result.StoreName}:[/]");
            AnsiConsole.MarkupLine($"  Subject: [bold]{Markup.Escape(subject)}[/]");
            AnsiConsole.MarkupLine($"  Thumbprint: [dim]{cert.Thumbprint}[/]");
            AnsiConsole.MarkupLine($"  Expires: {cert.NotAfter.ToUniversalTime():yyyy-MM-dd} UTC");
        }
    }

    public void WriteTrustRemoved(TrustOperationResult result)
    {
        if (!result.Success)
        {
            WriteError(result.ErrorMessage ?? "Unknown error");
            return;
        }

        foreach (var cert in result.Certificates)
        {
            var subject = GetSimpleName(cert.Subject);
            AnsiConsole.MarkupLine($"[green]Certificate removed from {result.StoreLocation}\\{result.StoreName}:[/]");
            AnsiConsole.MarkupLine($"  Subject: [bold]{Markup.Escape(subject)}[/]");
            AnsiConsole.MarkupLine($"  Thumbprint: [dim]{cert.Thumbprint}[/]");
        }

        if (result.Certificates.Count > 1)
        {
            AnsiConsole.MarkupLine($"[green]Total: {result.Certificates.Count} certificates removed.[/]");
        }
    }

    public void WriteConversionResult(ConversionResult result)
    {
        if (!result.Success)
        {
            WriteError("Conversion failed");
            return;
        }

        var table = new Table();
        table.Border(TableBorder.Rounded);
        table.AddColumn("Property");
        table.AddColumn("Value");

        table.AddRow("[bold]Status[/]", "[green]Success[/]");

        if (!string.IsNullOrEmpty(result.Subject))
        {
            table.AddRow("Subject", Markup.Escape(result.Subject));
        }

        if (!string.IsNullOrEmpty(result.OutputFormat))
        {
            table.AddRow("Output Format", result.OutputFormat);
        }

        // Input files
        if (result.InputCertificate != null)
        {
            table.AddRow("Input Certificate", Markup.Escape(result.InputCertificate));
        }
        if (result.InputKey != null)
        {
            table.AddRow("Input Key", Markup.Escape(result.InputKey));
        }
        if (result.InputPfx != null)
        {
            table.AddRow("Input PFX", Markup.Escape(result.InputPfx));
        }

        // Output files
        table.AddRow("[bold]Output File[/]", $"[blue]{Markup.Escape(result.OutputFile)}[/]");

        if (result.AdditionalOutputFiles.Length > 0)
        {
            foreach (var file in result.AdditionalOutputFiles)
            {
                table.AddRow("Additional Output", $"[blue]{Markup.Escape(file)}[/]");
            }
        }

        AnsiConsole.Write(table);

        // Password handling
        if (result.PasswordWasGenerated && result.GeneratedPassword != null)
        {
            AnsiConsole.WriteLine();
            var passwordPanel = new Panel(
                new Rows(
                    new Markup($"[bold cyan]{Markup.Escape(result.GeneratedPassword)}[/]"),
                    new Markup(""),
                    new Markup("[yellow]Store this password securely! This is your only chance to see it.[/]")
                ))
                .Header("[bold yellow]Generated Password[/]")
                .Border(BoxBorder.Double)
                .BorderColor(Color.Yellow);
            AnsiConsole.Write(passwordPanel);
        }
    }

    public void WriteExportResult(ExportResult result)
    {
        if (!result.Success)
        {
            WriteError("Export failed");
            return;
        }

        AnsiConsole.MarkupLine("[green]Successfully exported certificate![/]");
        AnsiConsole.WriteLine();

        // Certificate details
        AnsiConsole.MarkupLine($"[bold]Certificate:[/]");
        AnsiConsole.MarkupLine($"  Subject: {Markup.Escape(result.Subject)}");
        AnsiConsole.MarkupLine($"  Issuer: {Markup.Escape(result.Issuer)}");
        AnsiConsole.MarkupLine($"  Thumbprint: [dim]{result.Thumbprint}[/]");
        AnsiConsole.MarkupLine($"  Expires: {result.NotAfter.ToUniversalTime():yyyy-MM-dd} UTC");
        AnsiConsole.WriteLine();

        // Source
        AnsiConsole.MarkupLine($"[bold]Source:[/] {Markup.Escape(result.Source)}");
        AnsiConsole.WriteLine();

        // Output files
        AnsiConsole.MarkupLine("[bold]Saved Files:[/]");
        foreach (var file in result.OutputFiles)
        {
            AnsiConsole.MarkupLine($"  [blue]-[/] {Markup.Escape(Path.GetFileName(file))}");
        }

        // Password warning if generated
        if (result.PasswordWasGenerated && !string.IsNullOrEmpty(result.GeneratedPassword))
        {
            AnsiConsole.WriteLine();
            var passwordPanel = new Panel(
                new Rows(
                    new Markup($"[bold cyan]{Markup.Escape(result.GeneratedPassword)}[/]"),
                    new Markup(""),
                    new Markup("[yellow]Store this password securely! This is your only chance to see it.[/]")
                ))
                .Header("[bold yellow]Generated Password[/]")
                .Border(BoxBorder.Double)
                .BorderColor(Color.Yellow);
            AnsiConsole.Write(passwordPanel);
        }
    }

    public void WriteVerificationResult(CertificateVerificationResult result)
    {
        AnsiConsole.MarkupLine("[bold]Certificate Validation Report[/]");
        AnsiConsole.MarkupLine("[dim]========================[/]");
        AnsiConsole.WriteLine();

        AnsiConsole.MarkupLine($"[bold]Certificate:[/] {Markup.Escape(result.Subject)}");
        AnsiConsole.MarkupLine($"[bold]Thumbprint:[/] [dim]{result.Thumbprint}[/]");
        AnsiConsole.WriteLine();

        // 1. Expiration Check
        AnsiConsole.MarkupLine("[bold][[1]] Checking Expiration Status...[/]");
        var expCheck = result.ExpirationCheck;
        if (expCheck.IsExpired)
        {
            AnsiConsole.MarkupLine($"    [red][[FAIL]][/] {Markup.Escape(expCheck.Message ?? "Certificate expired")}");
        }
        else if (expCheck.IsNotYetValid)
        {
            AnsiConsole.MarkupLine($"    [red][[FAIL]][/] {Markup.Escape(expCheck.Message ?? "Certificate not yet valid")}");
        }
        else if (expCheck.IsExpiringSoon)
        {
            AnsiConsole.MarkupLine($"    [yellow][[WARN]][/] {Markup.Escape(expCheck.Message ?? "Certificate expiring soon")}");
        }
        else
        {
            AnsiConsole.MarkupLine($"    [green][[PASS]][/] {Markup.Escape(expCheck.Message ?? "Certificate is valid")}");
        }
        AnsiConsole.WriteLine();

        // 2. Chain Validation
        AnsiConsole.MarkupLine("[bold][[2]] Checking Certificate Chain...[/]");
        var chainCheck = result.ChainValidation;
        if (chainCheck.Passed)
        {
            AnsiConsole.MarkupLine($"    [green][[PASS]][/] Chain is valid");
            AnsiConsole.MarkupLine($"           Chain length: {chainCheck.ChainElements.Count} certificate(s)");
            for (int i = 0; i < chainCheck.ChainElements.Count; i++)
            {
                var indent = new string(' ', 11 + (i * 2));
                AnsiConsole.MarkupLine($"{indent}{i + 1}. {Markup.Escape(chainCheck.ChainElements[i])}");
            }
        }
        else
        {
            AnsiConsole.MarkupLine("    [red][[FAIL]][/] Chain validation failed");
            foreach (var error in chainCheck.Errors)
            {
                AnsiConsole.MarkupLine($"           - {Markup.Escape(error)}");
            }
        }
        AnsiConsole.WriteLine();

        // 3. Trust Check
        AnsiConsole.MarkupLine("[bold][[3]] Checking Trust Status...[/]");
        var trustCheck = result.TrustCheck;
        if (trustCheck.Passed && trustCheck.IsTrusted)
        {
            AnsiConsole.MarkupLine("    [green][[PASS]][/] Certificate chains to a trusted root");
        }
        else if (trustCheck.Passed && !trustCheck.IsTrusted)
        {
            AnsiConsole.MarkupLine($"    [yellow][[WARN]][/] {Markup.Escape(trustCheck.Message ?? "Root not trusted")}");
        }
        else
        {
            AnsiConsole.MarkupLine($"    [red][[FAIL]][/] {Markup.Escape(trustCheck.Message ?? "Trust check failed")}");
        }
        AnsiConsole.WriteLine();

        // 4. Revocation Check (if requested)
        if (result.RevocationCheck != null)
        {
            AnsiConsole.MarkupLine("[bold][[4]] Checking Revocation Status...[/]");
            var revCheck = result.RevocationCheck;
            if (revCheck.IsRevoked)
            {
                AnsiConsole.MarkupLine($"    [red][[FAIL]][/] {Markup.Escape(revCheck.Message ?? "Certificate revoked")}");
            }
            else if (revCheck.IsOffline)
            {
                AnsiConsole.MarkupLine($"    [yellow][[WARN]][/] {Markup.Escape(revCheck.Message ?? "Offline")}");
            }
            else
            {
                AnsiConsole.MarkupLine($"    [green][[PASS]][/] {Markup.Escape(revCheck.Message ?? "Not revoked")}");
            }
            AnsiConsole.WriteLine();
        }

        // Summary
        AnsiConsole.MarkupLine("[bold]Summary[/]");
        AnsiConsole.MarkupLine("[dim]-------[/]");
        if (result.Success)
        {
            AnsiConsole.MarkupLine("[green][[PASS]] Certificate validation SUCCESSFUL[/]");
            AnsiConsole.MarkupLine("        The certificate passed all validation checks.");
        }
        else
        {
            AnsiConsole.MarkupLine("[red][[FAIL]] Certificate validation FAILED[/]");
            AnsiConsole.MarkupLine("        See details above for specific failures.");
        }
    }

    public void WriteLintResult(LintResult result)
    {
        var statusColor = result.Passed ? "green" : "red";
        var statusText = result.Passed ? "PASSED" : "FAILED";

        AnsiConsole.Write(new Rule($"[bold]Certificate Lint: [{statusColor}]{statusText}[/][/]").LeftJustified());
        AnsiConsole.WriteLine();

        // Certificate info
        AnsiConsole.MarkupLine($"[bold]Subject:[/] {Markup.Escape(result.Subject)}");
        AnsiConsole.MarkupLine($"[bold]Thumbprint:[/] [dim]{result.Thumbprint}[/]");
        AnsiConsole.MarkupLine($"[bold]Policy Set:[/] {result.PolicySet}");
        AnsiConsole.MarkupLine($"[bold]Certificate Type:[/] {(result.IsCa ? (result.IsRoot ? "Root CA" : "Intermediate CA") : "End Entity")}");
        AnsiConsole.WriteLine();

        if (result.Findings.Count == 0)
        {
            AnsiConsole.MarkupLine("[green]No issues found.[/]");
            return;
        }

        // Summary
        var summaryParts = new List<string>();
        if (result.ErrorCount > 0)
            summaryParts.Add($"[red]{result.ErrorCount} error{(result.ErrorCount > 1 ? "s" : "")}[/]");
        if (result.WarningCount > 0)
            summaryParts.Add($"[yellow]{result.WarningCount} warning{(result.WarningCount > 1 ? "s" : "")}[/]");
        if (result.InfoCount > 0)
            summaryParts.Add($"[dim]{result.InfoCount} info[/]");

        AnsiConsole.MarkupLine($"[bold]Findings:[/] {string.Join(", ", summaryParts)}");
        AnsiConsole.WriteLine();

        // Details table
        var table = new Table()
            .Border(TableBorder.Rounded)
            .AddColumn(new TableColumn("[bold]Severity[/]").NoWrap())
            .AddColumn(new TableColumn("[bold]Rule[/]"))
            .AddColumn(new TableColumn("[bold]Details[/]"));

        foreach (var finding in result.Findings)
        {
            var severityColor = finding.Severity switch
            {
                LintSeverity.Error => "red",
                LintSeverity.Warning => "yellow",
                _ => "dim"
            };

            var severityText = finding.Severity.ToString().ToUpper();
            var ruleText = $"[bold]{finding.RuleId}[/]\n[dim]{Markup.Escape(finding.RuleName)}[/]";

            var messageText = Markup.Escape(finding.Message);
            if (finding.ActualValue != null)
            {
                messageText += $"\n[dim]Actual: {Markup.Escape(finding.ActualValue)}[/]";
            }
            if (finding.ExpectedValue != null)
            {
                messageText += $"\n[dim]Expected: {Markup.Escape(finding.ExpectedValue)}[/]";
            }
            messageText += $"\n[dim]Policy: {finding.Policy}[/]";

            table.AddRow(
                $"[{severityColor}]{severityText}[/]",
                ruleText,
                messageText);
        }

        AnsiConsole.Write(table);
    }

    public void WriteRenewResult(RenewResult result)
    {
        if (!result.Success)
        {
            AnsiConsole.MarkupLine("[red]Renewal Failed[/]");
            AnsiConsole.MarkupLine($"[red]Error:[/] {Markup.Escape(result.ErrorMessage ?? "Unknown error")}");
            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine("[bold]Original Certificate:[/]");
            AnsiConsole.MarkupLine($"  Subject: {Markup.Escape(result.OriginalSubject)}");
            if (!string.IsNullOrEmpty(result.OriginalThumbprint))
            {
                AnsiConsole.MarkupLine($"  Thumbprint: {result.OriginalThumbprint}");
            }
            if (result.OriginalNotAfter != DateTime.MinValue)
            {
                AnsiConsole.MarkupLine($"  Expires: {result.OriginalNotAfter.ToUniversalTime():yyyy-MM-dd} UTC");
            }
            return;
        }

        AnsiConsole.Write(new Rule("[green]Certificate Renewed[/]").LeftJustified());
        AnsiConsole.WriteLine();

        // Original vs Renewed comparison table
        var table = new Table()
            .Border(TableBorder.Rounded)
            .AddColumn(new TableColumn("[bold]Property[/]").NoWrap())
            .AddColumn(new TableColumn("[bold]Original[/]"))
            .AddColumn(new TableColumn("[bold]Renewed[/]"));

        table.AddRow("Subject", Markup.Escape(result.OriginalSubject), Markup.Escape(result.NewSubject ?? "-"));
        table.AddRow("Thumbprint",
            $"[dim]{result.OriginalThumbprint[..Math.Min(16, result.OriginalThumbprint.Length)]}...[/]",
            $"[cyan]{result.NewThumbprint?[..Math.Min(16, result.NewThumbprint?.Length ?? 0)]}...[/]");
        table.AddRow("Expires (UTC)",
            $"[yellow]{result.OriginalNotAfter.ToUniversalTime():yyyy-MM-dd}[/]",
            $"[green]{result.NewNotAfter?.ToUniversalTime():yyyy-MM-dd}[/]");

        AnsiConsole.Write(table);
        AnsiConsole.WriteLine();

        // Details
        AnsiConsole.MarkupLine($"[bold]Key:[/] {result.KeyType} {(result.KeyWasPreserved ? "[dim](preserved)[/]" : "[dim](new)[/]")}");

        if (result.SANs?.Length > 0)
        {
            AnsiConsole.MarkupLine($"[bold]SANs:[/] {string.Join(", ", result.SANs.Select(Markup.Escape))}");
        }

        AnsiConsole.MarkupLine($"[bold]Output:[/] {Markup.Escape(result.OutputFile ?? "")}");

        if (result.PasswordWasGenerated && result.Password != null)
        {
            AnsiConsole.WriteLine();
            var passwordPanel = new Panel(
                new Rows(
                    new Markup($"[bold cyan]{Markup.Escape(result.Password)}[/]"),
                    new Markup(""),
                    new Markup("[yellow]Store this password securely! This is your only chance to see it.[/]")
                ))
                .Header("[bold yellow]Generated Password[/]")
                .Border(BoxBorder.Double)
                .BorderColor(Color.Yellow);
            AnsiConsole.Write(passwordPanel);
        }
    }

    public void WriteMonitorResult(MonitorResult result, bool quietMode)
    {
        // Header
        AnsiConsole.MarkupLine("[bold]Certificate Expiration Monitor[/]");
        AnsiConsole.MarkupLine($"Threshold: [cyan]{result.WarnThreshold} days[/]");
        AnsiConsole.WriteLine();

        // Summary table
        var summaryTable = new Table();
        summaryTable.AddColumn("Status");
        summaryTable.AddColumn("Count");
        summaryTable.Border = TableBorder.Rounded;

        summaryTable.AddRow("[green]Valid[/]", result.ValidCount.ToString());
        summaryTable.AddRow("[yellow]Expiring[/]", result.ExpiringCount.ToString());
        summaryTable.AddRow("[red]Expired[/]", result.ExpiredCount.ToString());
        if (result.SkippedCount > 0)
        {
            summaryTable.AddRow("[dim]Skipped[/]", result.SkippedCount.ToString());
        }
        summaryTable.AddRow("[dim]Total[/]", result.TotalScanned.ToString());

        AnsiConsole.Write(summaryTable);
        AnsiConsole.WriteLine();

        // Certificate details
        var certs = quietMode
            ? result.Certificates.Where(c => c.IsWarning)
            : result.Certificates;

        if (certs.Any())
        {
            var table = new Table();
            table.AddColumn("Source");
            table.AddColumn("Subject");
            table.AddColumn("Expires (UTC)");
            table.AddColumn("Days");
            table.AddColumn("Status");
            table.Border = TableBorder.Rounded;

            foreach (var cert in certs.OrderBy(c => c.DaysRemaining))
            {
                var statusColor = cert.Status switch
                {
                    "Expired" => "red",
                    "Expiring" => "yellow",
                    "NotYetValid" => "blue",
                    _ => "green"
                };

                table.AddRow(
                    TruncateSource(cert.Source, 30),
                    GetSimpleName(cert.Subject),
                    cert.NotAfter.ToUniversalTime().ToString("yyyy-MM-dd"),
                    cert.DaysRemaining.ToString(),
                    $"[{statusColor}]{cert.Status}[/]"
                );
            }

            AnsiConsole.Write(table);
        }

        // Warnings (skipped files)
        if (result.Warnings.Count > 0)
        {
            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine("[yellow]Warnings:[/]");
            foreach (var warning in result.Warnings)
            {
                AnsiConsole.MarkupLine($"  [dim]{Markup.Escape(warning.Source)}:[/] [yellow]{Markup.Escape(warning.Reason)}[/]");
            }
        }

        // Errors
        if (result.Errors.Count > 0)
        {
            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine("[red]Errors:[/]");
            foreach (var error in result.Errors)
            {
                AnsiConsole.MarkupLine($"  [dim]{Markup.Escape(error.Source)}:[/] {Markup.Escape(error.Message)}");
            }
        }
    }

    /// <summary>
    /// Truncates a source path for display.
    /// </summary>
    private static string TruncateSource(string source, int maxLength)
    {
        if (source.Length <= maxLength)
        {
            return Markup.Escape(source);
        }

        // For file paths, try to preserve the filename
        var fileName = Path.GetFileName(source);
        if (fileName.Length < maxLength - 3)
        {
            return Markup.Escape("..." + source[(source.Length - maxLength + 3)..]);
        }

        return Markup.Escape(source[..maxLength] + "...");
    }

    public void WriteMultipleMatchesWarning(List<X509Certificate2> matchingCerts)
    {
        AnsiConsole.MarkupLine($"[yellow]Multiple certificates match ({matchingCerts.Count}).[/]");
        AnsiConsole.MarkupLine("[yellow]Use --force to remove all matching certificates, or specify a thumbprint for single removal.[/]");
        AnsiConsole.WriteLine();

        var table = new Table()
            .Border(TableBorder.Rounded)
            .AddColumn(new TableColumn("[bold]Subject[/]"))
            .AddColumn(new TableColumn("[bold]Thumbprint[/]").NoWrap())
            .AddColumn(new TableColumn("[bold]Expires (UTC)[/]").NoWrap());

        foreach (var cert in matchingCerts)
        {
            var subject = GetSimpleName(cert.Subject);
            table.AddRow(
                Markup.Escape(subject.Length > 50 ? subject[..47] + "..." : subject),
                cert.Thumbprint,
                cert.NotAfter.ToUniversalTime().ToString("yyyy-MM-dd")
            );
        }

        AnsiConsole.Write(table);
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

    public void WriteError(string message)
    {
        AnsiConsole.MarkupLine($"[red]Error:[/] {Markup.Escape(message)}");
    }

    public void WriteWarning(string message)
    {
        AnsiConsole.MarkupLine($"[yellow]Warning:[/] {Markup.Escape(message)}");
    }

    public void WriteSuccess(string message)
    {
        AnsiConsole.MarkupLine($"[green]{Markup.Escape(message)}[/]");
    }

    public void WriteExamples(string commandPath, CommandExample[] examples)
    {
        var header = string.IsNullOrEmpty(commandPath)
            ? "[bold]certz Examples[/]"
            : $"[bold]Examples for: certz {Markup.Escape(commandPath)}[/]";

        AnsiConsole.Write(new Rule(header).LeftJustified());
        AnsiConsole.WriteLine();

        foreach (var example in examples)
        {
            AnsiConsole.MarkupLine($"[green]#[/] {Markup.Escape(example.Description)}");
            AnsiConsole.MarkupLine(ColorizeCommand(example.Command));
            if (!string.IsNullOrEmpty(example.Notes))
            {
                AnsiConsole.MarkupLine($"[dim]  {Markup.Escape(example.Notes)}[/]");
            }
            AnsiConsole.WriteLine();
        }
    }

    public void WriteAllExamples(IReadOnlyDictionary<string, CommandExample[]> allExamples)
    {
        AnsiConsole.Write(new Rule("[bold]certz Examples[/]").LeftJustified());
        AnsiConsole.WriteLine();
        AnsiConsole.MarkupLine("[dim]Use 'certz examples <command>' to see examples for a specific command.[/]");
        AnsiConsole.WriteLine();

        foreach (var (commandPath, examples) in allExamples.OrderBy(kvp => kvp.Key))
        {
            var header = string.IsNullOrEmpty(commandPath)
                ? "[bold yellow]General[/]"
                : $"[bold yellow]certz {Markup.Escape(commandPath)}[/]";

            AnsiConsole.MarkupLine(header);

            foreach (var example in examples)
            {
                AnsiConsole.MarkupLine($"  [green]#[/] {Markup.Escape(example.Description)}");
                AnsiConsole.MarkupLine($"  {ColorizeCommand(example.Command)}");
            }
            AnsiConsole.WriteLine();
        }
    }

    private static readonly HashSet<string> SecondLevelSubcommands = new(StringComparer.OrdinalIgnoreCase)
    {
        "dev", "ca", "add", "remove", "list"
    };

    private static string ColorizeCommand(string command)
    {
        var tokens = command.Split(' ');
        var result = new System.Text.StringBuilder();

        for (int i = 0; i < tokens.Length; i++)
        {
            var token = Markup.Escape(tokens[i]);
            var prefix = i == 0 ? "" : " ";

            if (i == 0)
            {
                // "certz" — bold white
                result.Append($"[bold white]{token}[/]");
            }
            else if (tokens[i].StartsWith("--") || tokens[i].StartsWith("-"))
            {
                // --flag or -f — yellow
                result.Append($"{prefix}[yellow]{token}[/]");
            }
            else if (i == 1)
            {
                // top-level subcommand (convert, inspect, lint, ...) — cyan
                result.Append($"{prefix}[cyan]{token}[/]");
            }
            else if (i == 2 && SecondLevelSubcommands.Contains(tokens[i]))
            {
                // second-level subcommand (dev, ca, add, remove, list) — cyan
                result.Append($"{prefix}[cyan]{token}[/]");
            }
            else
            {
                // positional argument or flag value — green
                result.Append($"{prefix}[green]{token}[/]");
            }
        }

        return result.ToString();
    }
}
