using System.Text;
using System.Text.RegularExpressions;
using certz.Models;
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

    /// <summary>
    /// Renders a detailed certificate chain tree with key info, SANs, and signatures.
    /// </summary>
    /// <param name="chain">The chain elements to render.</param>
    /// <param name="isValid">Whether the chain is valid.</param>
    /// <param name="console">The Spectre.Console instance to write to.</param>
    void RenderDetailedChain(List<ChainElementInfo> chain, bool isValid, IAnsiConsole console);
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

    public void RenderDetailedChain(List<ChainElementInfo> chain, bool isValid, IAnsiConsole console)
    {
        var root = new Tree("[bold]Certificate Chain[/]");

        if (chain.Count == 0)
        {
            root.AddNode("[red]No chain elements found[/]");
            console.Write(root);
            return;
        }

        // Build tree from root CA down to end entity
        // Chain is ordered from end-entity (index 0) to root CA (last index)
        TreeNode? currentNode = null;
        for (int i = chain.Count - 1; i >= 0; i--)
        {
            var element = chain[i];
            var isEndEntity = i == 0;
            var nodeText = BuildDetailedNodeText(element, isEndEntity);

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
        if (!isValid)
        {
            console.MarkupLine("");
            console.MarkupLine("[red]Chain validation failed[/]");
        }
        else
        {
            console.MarkupLine("");
            console.MarkupLine("[green]Chain validation successful[/]");
        }
    }

    private static string BuildDetailedNodeText(ChainElementInfo element, bool isEndEntity)
    {
        var sb = new StringBuilder();

        // Certificate type indicator
        string typeLabel;
        if (isEndEntity)
        {
            typeLabel = "[blue]End Entity[/]";
        }
        else if (element.IsSelfSigned)
        {
            typeLabel = "[green]Root CA[/]";
        }
        else if (element.IsCa)
        {
            typeLabel = "[cyan]Intermediate CA[/]";
        }
        else
        {
            typeLabel = "[grey]Certificate[/]";
        }

        // Subject name (extract CN)
        var cn = ExtractCN(element.Subject) ?? element.Subject;
        sb.Append($"{typeLabel}: [bold]{Markup.Escape(cn)}[/]");

        // Validity status
        var now = DateTime.Now;
        if (element.NotAfter < now)
        {
            sb.Append(" [red](EXPIRED)[/]");
        }
        else if (element.NotBefore > now)
        {
            sb.Append(" [yellow](NOT YET VALID)[/]");
        }
        else if (element.DaysRemaining < 30)
        {
            sb.Append($" [yellow]({element.DaysRemaining} days remaining)[/]");
        }

        // Key info
        sb.Append($"\n  [dim]Key:[/] {element.KeyAlgorithm ?? "Unknown"}");
        if (element.KeySize > 0)
        {
            sb.Append($" ({element.KeySize}-bit)");
        }

        // Signature algorithm
        if (!string.IsNullOrEmpty(element.SignatureAlgorithm))
        {
            sb.Append($"\n  [dim]Signature:[/] {element.SignatureAlgorithm}");
        }

        // Validity period
        sb.Append($"\n  [dim]Valid:[/] {element.NotBefore:yyyy-MM-dd} to {element.NotAfter:yyyy-MM-dd}");

        // SANs for end-entity
        if (isEndEntity && element.SubjectAlternativeNames.Count > 0)
        {
            var sansDisplay = string.Join(", ", element.SubjectAlternativeNames.Take(5));
            if (element.SubjectAlternativeNames.Count > 5)
            {
                sansDisplay += $" (+{element.SubjectAlternativeNames.Count - 5} more)";
            }
            sb.Append($"\n  [dim]SANs:[/] {Markup.Escape(sansDisplay)}");
        }

        // Thumbprint (abbreviated)
        if (element.Thumbprint.Length >= 16)
        {
            sb.Append($"\n  [dim]Thumbprint:[/] {element.Thumbprint[..16]}...");
        }
        else
        {
            sb.Append($"\n  [dim]Thumbprint:[/] {element.Thumbprint}");
        }

        // Revocation status (if checked)
        if (!string.IsNullOrEmpty(element.RevocationStatus))
        {
            var statusColor = element.RevocationStatus switch
            {
                "OK" => "green",
                "Revoked" => "red",
                "Unknown" or "Offline" => "yellow",
                _ => "dim"
            };
            sb.Append($"\n  [dim]Revocation:[/] [{statusColor}]{element.RevocationStatus}[/]");
        }

        // Validation errors
        foreach (var error in element.ValidationErrors)
        {
            sb.Append($"\n  [red]- {Markup.Escape(error)}[/]");
        }

        return sb.ToString();
    }

    private static string? ExtractCN(string subject)
    {
        var match = Regex.Match(subject, @"CN=([^,]+)");
        return match.Success ? match.Groups[1].Value : null;
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
