using certz.Models;
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
        table.AddRow("[green]Valid From[/]", result.NotBefore.ToString("yyyy-MM-dd"));
        table.AddRow("[green]Valid Until[/]", result.NotAfter.ToString("yyyy-MM-dd"));
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

        // Output files section
        if (result.OutputFiles.Length > 0)
        {
            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine("[bold]Saved Files:[/]");
            foreach (var file in result.OutputFiles)
            {
                AnsiConsole.MarkupLine($"  [blue]-[/] {Markup.Escape(file)}");
            }
        }

        // Password warning if generated
        if (result.PasswordWasGenerated && !string.IsNullOrEmpty(result.Password))
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
}
