using certz.Formatters;
using certz.Models;
using certz.Options;
using certz.Services;

namespace certz.Commands.Renew;

/// <summary>
/// The renew command for extending certificate validity.
/// </summary>
internal static class RenewCommand
{
    /// <summary>
    /// Adds the renew command to the root command.
    /// </summary>
    internal static void AddRenewCommand(this RootCommand rootCommand)
    {
        var command = BuildRenewCommand();
        rootCommand.Add(command);
    }

    private static Command BuildRenewCommand()
    {
        // Source argument
        var sourceArgument = new Argument<string?>("source")
        {
            Description = "Existing certificate (file path or thumbprint)",
            Arity = ArgumentArity.ZeroOrOne
        };

        // Options
        var guidedOption = OptionBuilders.CreateGuidedOption();

        var daysOption = new Option<int?>("--days", "-d")
        {
            Description = "New validity period in days (default: same as original, max 398)"
        };

        var passwordOption = OptionBuilders.CreatePasswordOption();

        var outOption = new Option<FileInfo?>("--out", "-o")
        {
            Description = "Output file path (default: <original>-renewed.pfx)"
        };

        var outPasswordOption = new Option<string?>("--out-password")
        {
            Description = "Password for output file (generates if not specified)"
        };

        var keepKeyOption = new Option<bool>("--keep-key")
        {
            Description = "Preserve existing private key instead of generating new",
            DefaultValueFactory = _ => false
        };

        var issuerCertOption = OptionBuilders.CreateIssuerCertOption();
        var issuerKeyOption = OptionBuilders.CreateIssuerKeyOption();
        var issuerPasswordOption = OptionBuilders.CreateIssuerPasswordOption();

        var storeOption = new Option<string?>("--store")
        {
            Description = "Certificate store name for thumbprint lookup (My, Root, CA)"
        };

        var locationOption = new Option<string?>("--location", "-l")
        {
            Description = "Store location (CurrentUser, LocalMachine)"
        };

        var formatOption = OptionBuilders.CreateFormatOption();
        var dryRunOption = OptionBuilders.CreateDryRunOption();

        var command = new Command("renew", "Renew an existing certificate with extended validity")
        {
            sourceArgument,
            guidedOption,
            daysOption,
            passwordOption,
            outOption,
            outPasswordOption,
            keepKeyOption,
            issuerCertOption,
            issuerKeyOption,
            issuerPasswordOption,
            storeOption,
            locationOption,
            formatOption,
            dryRunOption
        };

        command.SetAction(async (parseResult) =>
        {
            var guided = parseResult.GetValue(guidedOption);
            var format = parseResult.GetValue(formatOption) ?? "text";
            var formatter = FormatterFactory.Create(format);
            var dryRun = parseResult.GetValue(dryRunOption);

            RenewOptions options;

            if (guided)
            {
                try
                {
                    options = CertificateWizard.RunRenewWizard();
                }
                catch (OperationCanceledException)
                {
                    Console.Error.WriteLine("Operation cancelled.");
                    return 0;
                }
            }
            else
            {
                var source = parseResult.GetValue(sourceArgument)
                    ?? throw new ArgumentException("Source argument is required. Use 'certz renew <source>' or 'certz renew --guided'.");

                options = new RenewOptions
                {
                    Source = source,
                    Days = parseResult.GetValue(daysOption),
                    Password = parseResult.GetValue(passwordOption),
                    OutputFile = parseResult.GetValue(outOption),
                    OutputPassword = parseResult.GetValue(outPasswordOption),
                    KeepKey = parseResult.GetValue(keepKeyOption),
                    IssuerCert = parseResult.GetValue(issuerCertOption),
                    IssuerKey = parseResult.GetValue(issuerKeyOption),
                    IssuerPassword = parseResult.GetValue(issuerPasswordOption),
                    StoreName = parseResult.GetValue(storeOption),
                    StoreLocation = parseResult.GetValue(locationOption)
                };
            }

            // Dry-run: load source cert and show what would be renewed without writing output
            if (dryRun)
            {
                var details = new List<DryRunDetail>
                {
                    new("Source", options.Source)
                };

                try
                {
                    var sourceCert = LoadSourceCertForDryRun(options);
                    if (sourceCert != null)
                    {
                        var originalDays = (sourceCert.NotAfter - sourceCert.NotBefore).Days;
                        var newDays = options.Days.HasValue
                            ? Math.Min(options.Days.Value, 398)
                            : Math.Min(originalDays, 398);

                        var newNotAfter = DateTimeOffset.UtcNow.Date.AddDays(newDays);
                        var isSelfSigned = sourceCert.Subject == sourceCert.Issuer;

                        var sans = ExtractSANsForDryRun(sourceCert);
                        var keyType = sourceCert.GetKeyAlgorithm()?.Contains("ECC") == true
                            ? "ECDSA"
                            : "RSA";

                        details.Add(new("Current Subject",   sourceCert.Subject));
                        details.Add(new("Current Expiry",    sourceCert.NotAfter.ToUniversalTime().ToString("yyyy-MM-dd") + " UTC"));
                        if (sans.Length > 0)
                            details.Add(new("Preserved SANs",   string.Join(", ", sans)));
                        details.Add(new("Key",               options.KeepKey ? $"{keyType} (preserved)" : $"{keyType} (new)"));
                        details.Add(new("New Days",          newDays.ToString()));
                        details.Add(new("New Expiry",        newNotAfter.ToString("yyyy-MM-dd") + " UTC"));
                        details.Add(new("Signed By",         isSelfSigned ? "self-signed" : (options.IssuerCert?.Name ?? "CA (--issuer-cert required)")));
                        sourceCert.Dispose();
                    }
                }
                catch (Exception ex)
                {
                    details.Add(new("Warning", $"Could not read source cert: {ex.Message}"));
                }

                var outputFile = options.OutputFile?.Name
                    ?? Path.GetFileNameWithoutExtension(options.Source) + "-renewed.pfx";
                details.Add(new("Output", outputFile));

                formatter.WriteDryRunResult(new DryRunResult
                {
                    Command = "renew",
                    Action = $"Renew certificate: {options.Source}",
                    Details = details.ToArray()
                });
                return 0;
            }

            var result = await RenewService.RenewCertificate(options);
            formatter.WriteRenewResult(result);

            // Return exit code based on result
            if (!result.Success)
            {
                // Exit code 2 for missing issuer (CA-signed cert), 1 for other errors
                return result.ErrorMessage?.Contains("CA") == true ? 2 : 1;
            }
            return 0;
        });

        return command;
    }

    private static X509Certificate2? LoadSourceCertForDryRun(RenewOptions options)
    {
        if (!File.Exists(options.Source)) return null;

        var ext = Path.GetExtension(options.Source).ToLowerInvariant();
        if (ext is ".pfx" or ".p12")
        {
            return X509CertificateLoader.LoadPkcs12FromFile(options.Source, options.Password);
        }
        return X509CertificateLoader.LoadCertificateFromFile(options.Source);
    }

    private static string[] ExtractSANsForDryRun(X509Certificate2 cert)
    {
        try
        {
            var sanExt = cert.Extensions
                .OfType<X509SubjectAlternativeNameExtension>()
                .FirstOrDefault();
            if (sanExt == null) return Array.Empty<string>();

            var names = new List<string>();
            foreach (var name in sanExt.EnumerateDnsNames()) names.Add(name);
            foreach (var ip in sanExt.EnumerateIPAddresses()) names.Add(ip.ToString());
            return names.ToArray();
        }
        catch
        {
            return Array.Empty<string>();
        }
    }
}
