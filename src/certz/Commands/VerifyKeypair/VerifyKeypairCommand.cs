using certz.Formatters;
using certz.Options;
using certz.Services;

namespace certz.Commands.VerifyKeypair;

/// <summary>
/// Verifies that a private key matches a certificate (or CSR) by comparing SubjectPublicKeyInfo.
/// </summary>
internal static class VerifyKeypairCommand
{
    internal static void AddVerifyKeypairCommand(this RootCommand rootCommand)
    {
        rootCommand.Add(BuildCommand());
    }

    private static Command BuildCommand()
    {
        var certOption = new Option<FileInfo?>("--cert")
        {
            Description = "Certificate file to check (PEM, DER, .crt, .cer)."
        };

        var csrOption = new Option<FileInfo?>("--csr")
        {
            Description = "CSR file to check, as an alternative to --cert (PEM only)."
        };

        var keyOption = new Option<FileInfo?>("--key")
        {
            Description = "Private key file (PEM, PKCS#1 or PKCS#8; encrypted requires --password)."
        };

        var pfxOption = new Option<FileInfo?>("--pfx")
        {
            Description = "PFX/PKCS#12 file -- self-checks the embedded cert against its embedded key."
        };

        var passwordOption = OptionBuilders.CreatePasswordOption();
        var formatOption = OptionBuilders.CreateFormatOption();

        var command = new Command(
            "verify-keypair",
            "Verify that a private key matches a certificate or CSR.")
        {
            certOption,
            csrOption,
            keyOption,
            pfxOption,
            passwordOption,
            formatOption
        };

        command.SetAction(parseResult =>
        {
            var cert = parseResult.GetValue(certOption);
            var csr = parseResult.GetValue(csrOption);
            var key = parseResult.GetValue(keyOption);
            var pfx = parseResult.GetValue(pfxOption);
            var password = parseResult.GetValue(passwordOption);
            var format = parseResult.GetValue(formatOption) ?? "text";
            var formatter = FormatterFactory.Create(format);

            ValidateInputCombination(cert, csr, key, pfx);

            VerifyKeypairResult result;
            if (pfx is not null)
            {
                result = VerifyKeypairService.VerifyPfxSelfCheck(pfx, password);
            }
            else if (csr is not null)
            {
                result = VerifyKeypairService.VerifyCsrAndKey(csr, key!, password);
            }
            else
            {
                result = VerifyKeypairService.VerifyCertAndKey(cert!, key!, password);
            }

            formatter.WriteVerifyKeypairResult(result);

            if (!result.Match)
            {
                throw new KeypairMismatchException();
            }
        });

        return command;
    }

    private static void ValidateInputCombination(FileInfo? cert, FileInfo? csr, FileInfo? key, FileInfo? pfx)
    {
        if (pfx is not null)
        {
            if (cert is not null || csr is not null || key is not null)
                throw new ArgumentException(
                    "--pfx is mutually exclusive with --cert, --csr, and --key.");
            return;
        }

        if (cert is not null && csr is not null)
            throw new ArgumentException("--cert and --csr are mutually exclusive.");

        if (cert is null && csr is null)
            throw new ArgumentException(
                "Specify one of: --cert <file> --key <file>, --csr <file> --key <file>, or --pfx <file> --password <pwd>.");

        if (key is null)
            throw new ArgumentException("--key is required when using --cert or --csr.");
    }
}
