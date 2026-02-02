using System.Text;
using Spectre.Console;

namespace certz.Services.Validation;

/// <summary>
/// Service for rendering certificate chains as visual trees.
/// </summary>
internal interface IChainVisualizer
{
    /// <summary>
    /// Renders a certificate chain as an ASCII tree.
    /// </summary>
    /// <param name="result">The chain validation result to render.</param>
    /// <param name="console">The Spectre.Console instance to write to.</param>
    void RenderChain(ChainValidationResult result, IAnsiConsole console);
}

/// <summary>
/// Default implementation using Spectre.Console Tree rendering.
/// </summary>
internal class ChainVisualizer : IChainVisualizer
{
    public void RenderChain(ChainValidationResult result, IAnsiConsole console)
    {
        var root = new Tree("[bold]Certificate Chain[/]");

        if (result.ChainElements.Count == 0)
        {
            root.AddNode("[red]No chain elements found[/]");
            console.Write(root);
            return;
        }

        // Build tree from root CA down to end entity
        // ChainElements are ordered from end-entity (index 0) to root CA (last index)
        // So we iterate in reverse to build the tree from root down
        TreeNode? currentNode = null;
        for (int i = result.ChainElements.Count - 1; i >= 0; i--)
        {
            var element = result.ChainElements[i];
            var cert = element.Certificate;

            var nodeText = BuildNodeText(cert, element.Status, i == 0);

            if (currentNode == null)
            {
                currentNode = root.AddNode(nodeText);
            }
            else
            {
                currentNode = currentNode.AddNode(nodeText);
            }
        }

        console.Write(root);

        // Show overall chain status
        if (!result.IsValid)
        {
            console.MarkupLine("");
            console.MarkupLine("[red]Chain validation failed:[/]");
            foreach (var status in result.ChainStatus.Where(s => s.Status != X509ChainStatusFlags.NoError))
            {
                console.MarkupLine($"  [yellow]- {Markup.Escape(status.StatusInformation)}[/]");
            }
        }
        else
        {
            console.MarkupLine("");
            console.MarkupLine("[green]Chain validation successful[/]");
        }
    }

    private static string BuildNodeText(X509Certificate2 cert, List<X509ChainStatus> status, bool isEndEntity)
    {
        var sb = new StringBuilder();

        // Determine certificate type based on Basic Constraints extension
        var basicConstraints = cert.Extensions["2.5.29.19"] as X509BasicConstraintsExtension;
        var isCA = basicConstraints?.CertificateAuthority ?? false;

        // Certificate type indicator
        string typeLabel;
        if (isEndEntity)
        {
            typeLabel = "[blue]End Entity[/]";
        }
        else if (isCA)
        {
            // Check if self-signed (Root CA)
            var isSelfSigned = cert.Subject == cert.Issuer;
            typeLabel = isSelfSigned ? "[green]Root CA[/]" : "[cyan]Intermediate CA[/]";
        }
        else
        {
            typeLabel = "[grey]Certificate[/]";
        }

        // Subject name
        var subject = cert.GetNameInfo(X509NameType.SimpleName, false);
        sb.Append($"{typeLabel}: [bold]{Markup.Escape(subject)}[/]");

        // Validity indicator
        var now = DateTime.Now;
        if (cert.NotAfter < now)
        {
            sb.Append(" [red](EXPIRED)[/]");
        }
        else if (cert.NotBefore > now)
        {
            sb.Append(" [yellow](NOT YET VALID)[/]");
        }
        else
        {
            var daysRemaining = (cert.NotAfter - now).Days;
            if (daysRemaining < 30)
            {
                sb.Append($" [yellow]({daysRemaining} days remaining)[/]");
            }
        }

        // Thumbprint (abbreviated for display)
        sb.Append($"\n  Thumbprint: [dim]{cert.Thumbprint[..16]}...[/]");

        // Expiration date
        sb.Append($"\n  Expires: [dim]{cert.NotAfter:yyyy-MM-dd}[/]");

        // Status issues
        foreach (var s in status.Where(s => s.Status != X509ChainStatusFlags.NoError))
        {
            sb.Append($"\n  [red]- {Markup.Escape(s.StatusInformation)}[/]");
        }

        return sb.ToString();
    }
}
