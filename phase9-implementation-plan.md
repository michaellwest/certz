# Phase 9: Enhanced Certificate Format Conversion

**Status:** In Progress
**Created:** 2026-02-09

## Objective

Enhance the `certz convert` command with DER format support and a simplified, intuitive interface. The goal is to provide "simple conversion commands between PEM, DER, and PFX that don't require memorizing complex export flags" as specified in the project requirements.

## Project Context

This is a .NET 10 CLI tool using:
- **System.CommandLine** for command parsing
- **Spectre.Console** for display formatting
- **Record types** for options and results

### Established Patterns

**Command Structure:** `Commands/<Feature>/<Feature>Command.cs`
- Static class with `Build<Feature>Command()` method
- Returns `Command` with options and `SetAction` handler
- Uses `OptionBuilders` for standard options
- Calls service layer, formats with `FormatterFactory.Create(format)`

**Service Layer:** `Services/<Feature>Service.cs`
- Static class with internal methods
- Returns result record types
- Contains business logic

**Models:** `Models/<Feature>Options.cs` and `Models/<Feature>Result.cs`
- Record types with `required` and `init` properties

**Testing:** `test/test-<feature>.ps1`
- PowerShell 7.5+ scripts
- Each test invokes certz.exe exactly ONCE
- Setup/cleanup in PowerShell only
- Assert system state, not console output

---

## Current State Analysis

### Existing Convert Command

The current `certz convert` command in `Commands/ConvertCommand.cs` supports:

| Conversion | Command |
|------------|---------|
| PEM → PFX | `certz convert --cert cert.pem --key key.pem --file output.pfx` |
| PFX → PEM | `certz convert --file input.pfx --out-cert cert.pem --out-key key.pem --password X` |

**Limitations:**
1. No DER format support
2. Complex flag combinations required
3. Must specify separate --cert and --key for input
4. Direction determined by which flags are present (confusing)

### Existing ConvertService

`Services/ConvertService.cs` provides:
- `ConvertToPfx()` - Combines PEM cert + key into PFX
- `ConvertFromPfx()` - Extracts PEM cert + key from PFX
- RSA and ECDSA key support
- Modern/legacy PFX encryption options

---

## Enhanced Command Specification

### New Simplified Interface

```
certz convert <input> --to <format> [options]

Arguments:
  input               Input certificate file (auto-detected format)

Options:
  --to, -t            Output format: pem, der, pfx (required)
  --output, -o        Output file path (default: input name with new extension)
  --key               Private key file (required for PFX output if input lacks key)
  --password, -p      Password for PFX (input or output)
  --password-file     Read/write password from/to file
  --pfx-encryption    PFX encryption: modern (default), legacy
  --include-key       Include private key in output (default: true for PFX)
  --format            Display format: text (default), json

Exit Codes:
  0 = Conversion successful
  1 = Invalid arguments or options
  2 = File not found or access denied
  3 = Conversion failed (format/key issues)
```

### Backward Compatibility

The existing flag-based interface remains functional:
```bash
# Old syntax still works
certz convert --cert cert.pem --key key.pem --file output.pfx
certz convert --file input.pfx --out-cert cert.pem --out-key key.pem -p secret
```

### New Simplified Examples

```bash
# PFX to PEM (extracts cert + key)
certz convert server.pfx --to pem -p secret

# PFX to DER (certificate only)
certz convert server.pfx --to der -p secret

# PEM to DER
certz convert server.pem --to der

# DER to PEM
certz convert server.der --to pem

# PEM to PFX (auto-finds matching .key file)
certz convert server.pem --to pfx

# PEM to PFX (explicit key file)
certz convert server.pem --to pfx --key server.key

# DER to PFX
certz convert server.der --to pfx --key server.key
```

---

## Format Details

### Supported Formats

| Format | Extensions | Description | Contains Key? |
|--------|------------|-------------|---------------|
| PEM | .pem, .crt, .cer | Base64 with BEGIN/END headers | Optional |
| DER | .der, .cer (binary) | Binary ASN.1 encoding | Optional |
| PFX | .pfx, .p12 | PKCS#12 bundle | Yes (typically) |

### Format Detection

**By Extension:**
| Extension | Default Format |
|-----------|----------------|
| .pfx, .p12 | PFX |
| .der | DER |
| .pem, .crt, .cer, .key | PEM (content-based) |

**By Content (for ambiguous extensions like .cer):**
- Starts with `-----BEGIN` → PEM
- Binary content → DER
- Contains PKCS#12 structure → PFX

### Output File Naming

When `--output` is not specified, derive from input:

| Input | --to | Output |
|-------|------|--------|
| server.pfx | pem | server.pem, server.key |
| server.pem | der | server.der |
| server.der | pem | server.pem |
| server.pem | pfx | server.pfx |

---

## Design Decisions

| Area | Decision | Rationale |
|------|----------|-----------|
| **Primary interface** | `<input> --to <format>` | Intuitive, matches common tools |
| **Format detection** | Extension first, content fallback | Fast, reliable |
| **Key auto-discovery** | Look for `<name>.key` if not provided | Common convention |
| **Default output path** | Same directory, new extension | Convenient |
| **Backward compatibility** | Keep old flags working | No breaking changes |
| **DER key format** | PKCS#8 DER | Standard format |
| **Combined PEM output** | Cert + key in single file option | Flexibility |

---

## Progress Tracker

| # | Step | Status | Notes |
|---|------|--------|-------|
| 1 | Add FormatType enum | [x] | Models/FormatType.cs |
| 2 | Add ConvertOptions model | [x] | Models/ConvertOptions.cs |
| 3 | Add format detection service | [x] | Services/FormatDetectionService.cs |
| 4 | Add DER conversion methods | [x] | Services/ConvertService.cs |
| 5 | Update ConvertCommand | [x] | Add new simplified interface |
| 6 | Update TextFormatter | [ ] | Enhanced conversion output |
| 7 | Update JsonFormatter | [ ] | Add format info fields |
| 8 | Create tests | [ ] | test/test-convert.ps1 |
| 9 | Update documentation | [ ] | README.md |

---

## Implementation Steps

### Step 1: Add FormatType Enum

**Create:** `Models/FormatType.cs`

```csharp
namespace certz.Models;

/// <summary>
/// Represents certificate file formats.
/// </summary>
public enum FormatType
{
    /// <summary>
    /// PEM format (Base64 with BEGIN/END headers).
    /// </summary>
    Pem,

    /// <summary>
    /// DER format (Binary ASN.1 encoding).
    /// </summary>
    Der,

    /// <summary>
    /// PFX/PKCS#12 format (Password-protected bundle).
    /// </summary>
    Pfx,

    /// <summary>
    /// Format could not be determined.
    /// </summary>
    Unknown
}
```

**Status:** [x] Complete

---

### Step 2: Add ConvertOptions Model

**Create:** `Models/ConvertOptions.cs`

```csharp
namespace certz.Models;

/// <summary>
/// Options for the simplified convert command.
/// </summary>
internal record ConvertOptions
{
    /// <summary>
    /// Input certificate file.
    /// </summary>
    public required FileInfo InputFile { get; init; }

    /// <summary>
    /// Detected format of the input file.
    /// </summary>
    public FormatType InputFormat { get; init; }

    /// <summary>
    /// Target output format.
    /// </summary>
    public required FormatType OutputFormat { get; init; }

    /// <summary>
    /// Output file path (null for auto-generated).
    /// </summary>
    public FileInfo? OutputFile { get; init; }

    /// <summary>
    /// Private key file (for PFX output when input lacks key).
    /// </summary>
    public FileInfo? KeyFile { get; init; }

    /// <summary>
    /// Password for PFX input/output.
    /// </summary>
    public string? Password { get; init; }

    /// <summary>
    /// File to read/write password.
    /// </summary>
    public FileInfo? PasswordFile { get; init; }

    /// <summary>
    /// PFX encryption mode: modern or legacy.
    /// </summary>
    public string PfxEncryption { get; init; } = "modern";

    /// <summary>
    /// Whether to include private key in output.
    /// </summary>
    public bool IncludeKey { get; init; } = true;
}
```

**Status:** [x] Complete

---

### Step 3: Add Format Detection Service

**Create:** `Services/FormatDetectionService.cs`

```csharp
using certz.Models;

namespace certz.Services;

/// <summary>
/// Detects certificate file formats from extension and content.
/// </summary>
internal static class FormatDetectionService
{
    private static readonly byte[] PemPrefix = "-----BEGIN"u8.ToArray();
    private static readonly byte[] Pkcs12Prefix = new byte[] { 0x30, 0x82 }; // ASN.1 SEQUENCE

    /// <summary>
    /// Detects the format of a certificate file.
    /// </summary>
    internal static async Task<FormatType> DetectFormat(FileInfo file)
    {
        // Check extension first
        var extension = file.Extension.ToLowerInvariant();

        switch (extension)
        {
            case ".pfx":
            case ".p12":
                return FormatType.Pfx;

            case ".der":
                return FormatType.Der;

            case ".pem":
                return FormatType.Pem;

            case ".crt":
            case ".cer":
            case ".key":
                // Ambiguous - check content
                return await DetectFromContent(file);

            default:
                return await DetectFromContent(file);
        }
    }

    /// <summary>
    /// Detects format from file content.
    /// </summary>
    private static async Task<FormatType> DetectFromContent(FileInfo file)
    {
        if (!file.Exists)
        {
            return FormatType.Unknown;
        }

        // Read first bytes to determine format
        var buffer = new byte[16];
        await using var stream = file.OpenRead();
        var bytesRead = await stream.ReadAsync(buffer);

        if (bytesRead == 0)
        {
            return FormatType.Unknown;
        }

        // Check for PEM header
        if (bytesRead >= PemPrefix.Length &&
            buffer.AsSpan(0, PemPrefix.Length).SequenceEqual(PemPrefix))
        {
            return FormatType.Pem;
        }

        // Check for binary ASN.1 (DER or PFX)
        if (bytesRead >= 2 && buffer[0] == 0x30)
        {
            // Both DER and PFX start with ASN.1 SEQUENCE
            // Try to determine if it's a PFX by checking for PKCS#12 structure
            // For simplicity, check file size - PFX is usually larger
            if (file.Length > 500)
            {
                // Could be PFX - try loading as PKCS#12
                return await TryDetectPfx(file) ? FormatType.Pfx : FormatType.Der;
            }
            return FormatType.Der;
        }

        return FormatType.Unknown;
    }

    /// <summary>
    /// Attempts to detect if a file is a PFX by trying to parse it.
    /// </summary>
    private static async Task<bool> TryDetectPfx(FileInfo file)
    {
        try
        {
            // Read entire file
            var data = await File.ReadAllBytesAsync(file.FullName);

            // Try to parse as PKCS#12 with empty password
            // This will fail for password-protected PFX but the exception type helps
            try
            {
                var cert = new System.Security.Cryptography.X509Certificates.X509Certificate2(data);
                cert.Dispose();
                return true;
            }
            catch (System.Security.Cryptography.CryptographicException ex)
            {
                // "The specified network password is not correct" indicates PFX
                return ex.Message.Contains("password", StringComparison.OrdinalIgnoreCase);
            }
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Parses a format string to FormatType enum.
    /// </summary>
    internal static FormatType ParseFormat(string format)
    {
        return format.ToLowerInvariant() switch
        {
            "pem" => FormatType.Pem,
            "der" => FormatType.Der,
            "pfx" or "pkcs12" or "p12" => FormatType.Pfx,
            _ => FormatType.Unknown
        };
    }

    /// <summary>
    /// Gets the default file extension for a format.
    /// </summary>
    internal static string GetDefaultExtension(FormatType format)
    {
        return format switch
        {
            FormatType.Pem => ".pem",
            FormatType.Der => ".der",
            FormatType.Pfx => ".pfx",
            _ => ".bin"
        };
    }

    /// <summary>
    /// Generates output path based on input and target format.
    /// </summary>
    internal static string GenerateOutputPath(FileInfo input, FormatType outputFormat)
    {
        var directory = input.DirectoryName ?? ".";
        var baseName = Path.GetFileNameWithoutExtension(input.Name);
        var extension = GetDefaultExtension(outputFormat);

        return Path.Combine(directory, baseName + extension);
    }

    /// <summary>
    /// Attempts to find a matching key file for a certificate.
    /// </summary>
    internal static FileInfo? FindKeyFile(FileInfo certFile)
    {
        var directory = certFile.DirectoryName ?? ".";
        var baseName = Path.GetFileNameWithoutExtension(certFile.Name);

        // Try common key file naming patterns
        var patterns = new[]
        {
            $"{baseName}.key",
            $"{baseName}-key.pem",
            $"{baseName}.key.pem",
            $"{baseName}_key.pem"
        };

        foreach (var pattern in patterns)
        {
            var keyPath = Path.Combine(directory, pattern);
            if (File.Exists(keyPath))
            {
                return new FileInfo(keyPath);
            }
        }

        return null;
    }
}
```

**Status:** [x] Complete

---

### Step 4: Add DER Conversion Methods to ConvertService

**Modify:** `Services/ConvertService.cs`

Add the following methods:

```csharp
/// <summary>
/// Converts a certificate to DER format.
/// </summary>
internal static async Task<ConversionResult> ConvertToDer(ConvertOptions options)
{
    // Load certificate based on input format
    var certificate = await LoadCertificate(options);

    // Determine output path
    var outputPath = options.OutputFile?.FullName
        ?? FormatDetectionService.GenerateOutputPath(options.InputFile, FormatType.Der);

    // Create output directory if needed
    var outputDir = Path.GetDirectoryName(outputPath);
    if (!string.IsNullOrEmpty(outputDir))
    {
        Directory.CreateDirectory(outputDir);
    }

    // Export certificate as DER (binary)
    await File.WriteAllBytesAsync(outputPath, certificate.RawData);

    var subject = certificate.SubjectName.Format(false);
    certificate.Dispose();

    return new ConversionResult
    {
        Success = true,
        OutputFile = outputPath,
        InputPfx = options.InputFormat == FormatType.Pfx ? options.InputFile.FullName : null,
        InputCertificate = options.InputFormat == FormatType.Pem ? options.InputFile.FullName : null,
        Subject = subject,
        OutputFormat = "DER"
    };
}

/// <summary>
/// Converts a certificate to PEM format.
/// </summary>
internal static async Task<ConversionResult> ConvertToPem(ConvertOptions options)
{
    // Load certificate based on input format
    var certificate = await LoadCertificate(options);

    // Determine output path
    var outputPath = options.OutputFile?.FullName
        ?? FormatDetectionService.GenerateOutputPath(options.InputFile, FormatType.Pem);

    // Create output directory if needed
    var outputDir = Path.GetDirectoryName(outputPath);
    if (!string.IsNullOrEmpty(outputDir))
    {
        Directory.CreateDirectory(outputDir);
    }

    var sb = new System.Text.StringBuilder();

    // Export certificate as PEM
    var certPem = PemEncoding.Write("CERTIFICATE", certificate.RawData);
    sb.AppendLine(new string(certPem));

    // Export private key if present and requested
    var additionalFiles = new List<string>();
    if (options.IncludeKey && certificate.HasPrivateKey)
    {
        var keyPem = ExportPrivateKeyPem(certificate);
        if (keyPem != null)
        {
            // Write key to separate file
            var keyPath = Path.Combine(
                Path.GetDirectoryName(outputPath) ?? ".",
                Path.GetFileNameWithoutExtension(outputPath) + ".key");

            await File.WriteAllTextAsync(keyPath, keyPem);
            additionalFiles.Add(keyPath);
        }
    }

    await File.WriteAllTextAsync(outputPath, sb.ToString());

    var subject = certificate.SubjectName.Format(false);
    certificate.Dispose();

    return new ConversionResult
    {
        Success = true,
        OutputFile = outputPath,
        InputPfx = options.InputFormat == FormatType.Pfx ? options.InputFile.FullName : null,
        AdditionalOutputFiles = additionalFiles.ToArray(),
        Subject = subject,
        OutputFormat = "PEM"
    };
}

/// <summary>
/// Converts a certificate to PFX format using the simplified interface.
/// </summary>
internal static async Task<ConversionResult> ConvertToPfxSimple(ConvertOptions options)
{
    // Load certificate based on input format
    var certificate = await LoadCertificate(options);

    // If certificate doesn't have key, try to load from key file
    if (!certificate.HasPrivateKey)
    {
        var keyFile = options.KeyFile ?? FormatDetectionService.FindKeyFile(options.InputFile);
        if (keyFile == null || !keyFile.Exists)
        {
            throw new ArgumentException(
                "Private key required for PFX output. Use --key to specify the key file.");
        }

        certificate = await AttachPrivateKey(certificate, keyFile);
    }

    // Handle password
    bool passwordWasGenerated = false;
    var password = options.Password;

    if (string.IsNullOrEmpty(password) && options.PasswordFile?.Exists == true)
    {
        password = (await File.ReadAllTextAsync(options.PasswordFile.FullName)).Trim();
    }

    if (string.IsNullOrEmpty(password))
    {
        password = CertificateUtilities.GenerateSecurePassword();
        passwordWasGenerated = true;
    }

    // Determine output path
    var outputPath = options.OutputFile?.FullName
        ?? FormatDetectionService.GenerateOutputPath(options.InputFile, FormatType.Pfx);

    // Create output directory if needed
    var outputDir = Path.GetDirectoryName(outputPath);
    if (!string.IsNullOrEmpty(outputDir))
    {
        Directory.CreateDirectory(outputDir);
    }

    // Export as PFX
    byte[] pfxData;
    if (options.PfxEncryption.Equals("modern", StringComparison.OrdinalIgnoreCase))
    {
        var pbeParams = new PbeParameters(
            PbeEncryptionAlgorithm.Aes256Cbc,
            HashAlgorithmName.SHA256,
            iterationCount: 100000);
        pfxData = certificate.ExportPkcs12(pbeParams, password);
    }
    else
    {
        pfxData = certificate.Export(X509ContentType.Pfx, password);
    }

    await File.WriteAllBytesAsync(outputPath, pfxData);

    // Write password to file if generated
    if (passwordWasGenerated && options.PasswordFile != null)
    {
        options.PasswordFile.Directory?.Create();
        await File.WriteAllTextAsync(options.PasswordFile.FullName, password);
    }

    var subject = certificate.SubjectName.Format(false);
    certificate.Dispose();

    return new ConversionResult
    {
        Success = true,
        OutputFile = outputPath,
        InputCertificate = options.InputFile.FullName,
        InputKey = options.KeyFile?.FullName,
        GeneratedPassword = passwordWasGenerated ? password : null,
        PasswordWasGenerated = passwordWasGenerated,
        Subject = subject,
        OutputFormat = "PFX"
    };
}

/// <summary>
/// Loads a certificate from a file based on detected format.
/// </summary>
private static async Task<X509Certificate2> LoadCertificate(ConvertOptions options)
{
    var format = options.InputFormat != FormatType.Unknown
        ? options.InputFormat
        : await FormatDetectionService.DetectFormat(options.InputFile);

    return format switch
    {
        FormatType.Pfx => LoadPfxCertificate(options),
        FormatType.Der => LoadDerCertificate(options.InputFile),
        FormatType.Pem => await LoadPemCertificate(options.InputFile),
        _ => throw new ArgumentException($"Unable to detect format of {options.InputFile.Name}")
    };
}

private static X509Certificate2 LoadPfxCertificate(ConvertOptions options)
{
    if (string.IsNullOrEmpty(options.Password))
    {
        throw new ArgumentException("Password required for PFX input. Use --password to specify.");
    }

    return X509CertificateLoader.LoadPkcs12FromFile(
        options.InputFile.FullName,
        options.Password,
        X509KeyStorageFlags.Exportable);
}

private static X509Certificate2 LoadDerCertificate(FileInfo file)
{
    return new X509Certificate2(file.FullName);
}

private static async Task<X509Certificate2> LoadPemCertificate(FileInfo file)
{
    var text = await File.ReadAllTextAsync(file.FullName);
    return X509Certificate2.CreateFromPem(text);
}

/// <summary>
/// Attaches a private key from a file to a certificate.
/// </summary>
private static async Task<X509Certificate2> AttachPrivateKey(X509Certificate2 cert, FileInfo keyFile)
{
    var keyText = await File.ReadAllTextAsync(keyFile.FullName);

    // Try RSA first
    try
    {
        using var rsa = RSA.Create();
        rsa.ImportFromPem(keyText);
        return cert.CopyWithPrivateKey(rsa);
    }
    catch
    {
        // Try ECDSA
        try
        {
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportFromPem(keyText);
            return cert.CopyWithPrivateKey(ecdsa);
        }
        catch
        {
            throw new CertificateException(
                "Unable to import private key. Only RSA and ECDSA keys are supported.");
        }
    }
}

/// <summary>
/// Exports a certificate's private key as PEM.
/// </summary>
private static string? ExportPrivateKeyPem(X509Certificate2 certificate)
{
    var rsaKey = certificate.GetRSAPrivateKey();
    if (rsaKey != null)
    {
        return rsaKey.ExportPkcs8PrivateKeyPem();
    }

    var ecdsaKey = certificate.GetECDsaPrivateKey();
    if (ecdsaKey != null)
    {
        return ecdsaKey.ExportPkcs8PrivateKeyPem();
    }

    return null;
}
```

**Update ConversionResult model to include OutputFormat:**

```csharp
// In Models/ConversionResult.cs, add:
public string? OutputFormat { get; init; }
```

**Status:** [x] Complete

---

### Step 5: Update ConvertCommand with Simplified Interface

**Modify:** `Commands/ConvertCommand.cs`

```csharp
using certz.Formatters;
using certz.Models;
using certz.Options;
using certz.Services;

namespace certz.Commands;

internal static class ConvertCommand
{
    internal static void AddConvertCommand(this RootCommand rootCommand)
    {
        var command = BuildConvertCommand();
        rootCommand.Add(command);
    }

    private static Command BuildConvertCommand()
    {
        // === New simplified interface arguments/options ===
        var inputArgument = new Argument<FileInfo?>("input")
        {
            Description = "Input certificate file (format auto-detected)",
            Arity = ArgumentArity.ZeroOrOne
        };

        var toOption = new Option<string?>("--to", "-t")
        {
            Description = "Output format: pem, der, pfx"
        };
        toOption.AddValidator(result =>
        {
            var value = result.GetValueOrDefault<string?>();
            if (value != null && FormatDetectionService.ParseFormat(value) == FormatType.Unknown)
            {
                result.AddError("--to must be one of: pem, der, pfx");
            }
        });

        var outputOption = new Option<FileInfo?>("--output", "-o")
        {
            Description = "Output file path (default: auto-generated from input)"
        };

        // === Legacy interface options (kept for backward compatibility) ===
        var certOption = OptionBuilders.CreateFileOption(false, new[] { "--cert", "--c" });
        var keyOption = OptionBuilders.CreateFileOption(false, new[] { "--key", "--k" });
        var pfxOption = OptionBuilders.CreateFileOption(false, new[] { "--file", "--f", "--pfx" });
        var passwordOption = OptionBuilders.CreatePasswordOption();
        var passwordFileOption = OptionBuilders.CreatePasswordFileOption();
        var outputCertOption = OptionBuilders.CreateOutputCertOption();
        var outputKeyOption = OptionBuilders.CreateOutputKeyOption();
        var pfxEncryptionOption = OptionBuilders.CreatePfxEncryptionOption();
        var formatOption = OptionBuilders.CreateFormatOption();
        var includeKeyOption = new Option<bool>("--include-key")
        {
            Description = "Include private key in output (default: true for PFX)",
            DefaultValueFactory = _ => true
        };

        var convertCommand = new Command("convert",
            "Converts between certificate formats (PEM, DER, PFX).\n\n" +
            "Examples:\n" +
            "  certz convert server.pfx --to pem -p secret\n" +
            "  certz convert server.pem --to der\n" +
            "  certz convert server.der --to pfx --key server.key");

        // Add new interface
        convertCommand.Arguments.Add(inputArgument);
        convertCommand.Options.Add(toOption);
        convertCommand.Options.Add(outputOption);
        convertCommand.Options.Add(includeKeyOption);

        // Add legacy interface options
        convertCommand.Options.Add(certOption);
        convertCommand.Options.Add(keyOption);
        convertCommand.Options.Add(pfxOption);
        convertCommand.Options.Add(passwordOption);
        convertCommand.Options.Add(passwordFileOption);
        convertCommand.Options.Add(outputCertOption);
        convertCommand.Options.Add(outputKeyOption);
        convertCommand.Options.Add(pfxEncryptionOption);
        convertCommand.Options.Add(formatOption);

        convertCommand.SetAction(async (parseResult) =>
        {
            var input = parseResult.GetValue(inputArgument);
            var to = parseResult.GetValue(toOption);
            var output = parseResult.GetValue(outputOption);
            var key = parseResult.GetValue(keyOption);
            var password = parseResult.GetValue(passwordOption);
            var passwordFile = parseResult.GetValue(passwordFileOption);
            var pfxEncryption = parseResult.GetValue(pfxEncryptionOption) ?? "modern";
            var includeKey = parseResult.GetValue(includeKeyOption);
            var format = parseResult.GetValue(formatOption) ?? "text";
            var formatter = FormatterFactory.Create(format);

            // Legacy interface options
            var cert = parseResult.GetValue(certOption);
            var pfx = parseResult.GetValue(pfxOption);
            var outCert = parseResult.GetValue(outputCertOption);
            var outKey = parseResult.GetValue(outputKeyOption);

            // Determine which interface is being used
            if (input != null && to != null)
            {
                // === New simplified interface ===
                await HandleSimplifiedConversion(
                    input, to, output, key, password, passwordFile,
                    pfxEncryption, includeKey, formatter);
            }
            else if (cert != null && key != null && pfx != null)
            {
                // === Legacy: PEM to PFX ===
                var options = new ConvertToPfxOptions
                {
                    CertFile = cert,
                    KeyFile = key,
                    OutputFile = pfx,
                    Password = password,
                    PasswordFile = passwordFile,
                    PfxEncryption = pfxEncryption
                };
                var result = await ConvertService.ConvertToPfx(options);
                formatter.WriteConversionResult(result);
            }
            else if (pfx != null && (outCert != null || outKey != null))
            {
                // === Legacy: PFX to PEM ===
                if (string.IsNullOrEmpty(password) && passwordFile?.Exists == true)
                {
                    password = (await File.ReadAllTextAsync(passwordFile.FullName)).Trim();
                }

                if (string.IsNullOrEmpty(password))
                {
                    throw new ArgumentException(
                        "Password is required for PFX file. Use --password or --password-file.");
                }

                var options = new ConvertFromPfxOptions
                {
                    PfxFile = pfx,
                    Password = password,
                    OutputCert = outCert,
                    OutputKey = outKey
                };
                var result = await ConvertService.ConvertFromPfx(options);
                formatter.WriteConversionResult(result);
            }
            else
            {
                throw new ArgumentException(
                    "Please specify conversion parameters:\n\n" +
                    "Simplified interface:\n" +
                    "  certz convert <input> --to <pem|der|pfx> [options]\n\n" +
                    "Legacy interface:\n" +
                    "  PEM to PFX: --cert <file> --key <file> --pfx <output>\n" +
                    "  PFX to PEM: --pfx <file> --out-cert <output> --out-key <output>");
            }
        });

        return convertCommand;
    }

    private static async Task HandleSimplifiedConversion(
        FileInfo input,
        string to,
        FileInfo? output,
        FileInfo? key,
        string? password,
        FileInfo? passwordFile,
        string pfxEncryption,
        bool includeKey,
        IOutputFormatter formatter)
    {
        if (!input.Exists)
        {
            throw new FileNotFoundException($"Input file not found: {input.FullName}");
        }

        var inputFormat = await FormatDetectionService.DetectFormat(input);
        var outputFormat = FormatDetectionService.ParseFormat(to);

        if (inputFormat == FormatType.Unknown)
        {
            throw new ArgumentException($"Unable to detect format of {input.Name}. Check file content.");
        }

        if (inputFormat == outputFormat)
        {
            throw new ArgumentException(
                $"Input and output formats are the same ({inputFormat}). No conversion needed.");
        }

        var options = new ConvertOptions
        {
            InputFile = input,
            InputFormat = inputFormat,
            OutputFormat = outputFormat,
            OutputFile = output,
            KeyFile = key,
            Password = password,
            PasswordFile = passwordFile,
            PfxEncryption = pfxEncryption,
            IncludeKey = includeKey
        };

        var result = outputFormat switch
        {
            FormatType.Pem => await ConvertService.ConvertToPem(options),
            FormatType.Der => await ConvertService.ConvertToDer(options),
            FormatType.Pfx => await ConvertService.ConvertToPfxSimple(options),
            _ => throw new ArgumentException($"Unsupported output format: {to}")
        };

        formatter.WriteConversionResult(result);
    }
}
```

**Status:** [x] Complete

---

### Step 6: Update Option Builders

**Modify:** `Options/OptionBuilders.cs`

Add the `--to` option builder:

```csharp
/// <summary>
/// Creates the --to option for output format specification.
/// </summary>
internal static Option<string?> CreateToFormatOption()
{
    var option = new Option<string?>("--to", "-t")
    {
        Description = "Output format: pem, der, pfx"
    };

    option.AddValidator(result =>
    {
        var value = result.GetValueOrDefault<string?>();
        if (value != null)
        {
            var validFormats = new[] { "pem", "der", "pfx", "pkcs12", "p12" };
            if (!validFormats.Contains(value.ToLowerInvariant()))
            {
                result.AddError("--to must be one of: pem, der, pfx");
            }
        }
    });

    return option;
}

/// <summary>
/// Creates the --output option for specifying output file path.
/// </summary>
internal static Option<FileInfo?> CreateOutputOption()
{
    return new Option<FileInfo?>("--output", "-o")
    {
        Description = "Output file path (default: auto-generated from input)"
    };
}
```

**Status:** [ ] Not Started

---

### Step 7: Update TextFormatter

**Modify:** `Formatters/TextFormatter.cs`

Enhance the `WriteConversionResult` method:

```csharp
public void WriteConversionResult(ConversionResult result)
{
    if (!result.Success)
    {
        WriteError("Conversion failed.");
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
        CertificateUtilities.DisplayPasswordWarning(result.GeneratedPassword, null, false);
    }
}
```

**Status:** [ ] Not Started

---

### Step 8: Update JsonFormatter

**Modify:** `Formatters/JsonFormatter.cs`

Update the output record and method:

```csharp
internal record ConversionOutput(
    bool Success,
    string? Subject,
    string? OutputFormat,
    string OutputFile,
    string[]? AdditionalOutputFiles,
    string? InputCertificate,
    string? InputKey,
    string? InputPfx,
    string? GeneratedPassword,
    bool PasswordWasGenerated
);

public void WriteConversionResult(ConversionResult result)
{
    var output = new ConversionOutput(
        result.Success,
        result.Subject,
        result.OutputFormat,
        result.OutputFile,
        result.AdditionalOutputFiles.Length > 0 ? result.AdditionalOutputFiles : null,
        result.InputCertificate,
        result.InputKey,
        result.InputPfx,
        result.GeneratedPassword,
        result.PasswordWasGenerated
    );

    AnsiConsole.WriteLine(JsonSerializer.Serialize(output, _jsonOptions));
}
```

**Status:** [ ] Not Started

---

### Step 9: Create Tests

**Create:** `test/test-convert.ps1`

```powershell
#Requires -Version 7.5

<#
.SYNOPSIS
    Tests for certificate format conversion.
#>

param(
    [string[]]$TestId,
    [string[]]$Category
)

. "$PSScriptRoot\test-helper.ps1"

$TestCategories = @{
    "pem-to-der"  = @("conv-1.1", "conv-1.2")
    "der-to-pem"  = @("conv-2.1", "conv-2.2")
    "pem-to-pfx"  = @("conv-3.1", "conv-3.2", "conv-3.3")
    "pfx-to-pem"  = @("conv-4.1", "conv-4.2")
    "pfx-to-der"  = @("conv-5.1")
    "der-to-pfx"  = @("conv-6.1")
    "detection"   = @("conv-7.1", "conv-7.2", "conv-7.3")
    "errors"      = @("conv-8.1", "conv-8.2", "conv-8.3")
}

Initialize-TestEnvironment -TestId $TestId -Category $Category -TestCategories $TestCategories
Build-Certz

Write-TestHeader "Certificate Format Conversion Tests"
Write-Host "========================================`n"

# Create test certificates for conversion
$tempDir = New-TestDirectory "convert-tests"
Push-Location $tempDir

try {
    # Setup: Create a dev certificate for testing
    & certz create dev convert-test.local --file test.pfx --cert test.pem --key test.key --password "TestPass123" 2>&1 | Out-Null

    # ============================================================================
    # PEM TO DER TESTS
    # ============================================================================

    Write-TestHeader "PEM to DER Conversion"

    # conv-1.1: Basic PEM to DER
    Invoke-Test -TestId "conv-1.1" -TestName "Convert PEM certificate to DER" -TestScript {
        & certz convert test.pem --to der 2>&1 | Out-Null

        if (Test-Path "test.der") {
            # Verify it's binary (DER files don't start with -----)
            $content = [System.IO.File]::ReadAllBytes("test.der")
            $isBinary = $content[0] -eq 0x30  # ASN.1 SEQUENCE tag

            if ($isBinary) {
                return @{ Success = $true; Details = "PEM converted to DER successfully" }
            }
            return @{ Success = $false; Details = "Output is not valid DER format" }
        }
        return @{ Success = $false; Details = "Output file test.der not created" }
    }

    # conv-1.2: PEM to DER with custom output
    Invoke-Test -TestId "conv-1.2" -TestName "Convert PEM to DER with custom output path" -TestScript {
        & certz convert test.pem --to der --output custom.der 2>&1 | Out-Null

        if (Test-Path "custom.der") {
            return @{ Success = $true; Details = "Custom output path works" }
        }
        return @{ Success = $false; Details = "custom.der not created" }
    }

    # ============================================================================
    # DER TO PEM TESTS
    # ============================================================================

    Write-TestHeader "DER to PEM Conversion"

    # conv-2.1: Basic DER to PEM
    Invoke-Test -TestId "conv-2.1" -TestName "Convert DER certificate to PEM" -TestScript {
        # First ensure we have a DER file
        if (-not (Test-Path "test.der")) {
            & certz convert test.pem --to der 2>&1 | Out-Null
        }

        & certz convert test.der --to pem --output from-der.pem 2>&1 | Out-Null

        if (Test-Path "from-der.pem") {
            $content = Get-Content "from-der.pem" -Raw
            if ($content -match "-----BEGIN CERTIFICATE-----") {
                return @{ Success = $true; Details = "DER converted to PEM successfully" }
            }
            return @{ Success = $false; Details = "Output missing PEM headers" }
        }
        return @{ Success = $false; Details = "Output file not created" }
    }

    # conv-2.2: DER to PEM with JSON output
    Invoke-Test -TestId "conv-2.2" -TestName "DER to PEM with JSON format" -TestScript {
        $output = & certz convert test.der --to pem --output json-test.pem --format json 2>&1

        try {
            $json = $output | ConvertFrom-Json
            if ($json.success -and $json.outputFormat -eq "PEM") {
                return @{ Success = $true; Details = "JSON output correct" }
            }
            return @{ Success = $false; Details = "JSON missing expected fields" }
        }
        catch {
            return @{ Success = $false; Details = "Invalid JSON output" }
        }
    }

    # ============================================================================
    # PEM TO PFX TESTS
    # ============================================================================

    Write-TestHeader "PEM to PFX Conversion"

    # conv-3.1: PEM to PFX with explicit key
    Invoke-Test -TestId "conv-3.1" -TestName "Convert PEM to PFX with explicit key file" -TestScript {
        & certz convert test.pem --to pfx --key test.key --password "NewPass" --output explicit.pfx 2>&1 | Out-Null

        if (Test-Path "explicit.pfx") {
            # Verify we can load it
            try {
                $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
                    (Resolve-Path "explicit.pfx").Path, "NewPass")
                $hasKey = $cert.HasPrivateKey
                $cert.Dispose()

                if ($hasKey) {
                    return @{ Success = $true; Details = "PFX created with private key" }
                }
                return @{ Success = $false; Details = "PFX missing private key" }
            }
            catch {
                return @{ Success = $false; Details = "Failed to load PFX: $_" }
            }
        }
        return @{ Success = $false; Details = "PFX file not created" }
    }

    # conv-3.2: PEM to PFX with auto-discovered key
    Invoke-Test -TestId "conv-3.2" -TestName "Convert PEM to PFX with auto-discovered key" -TestScript {
        # test.pem should auto-find test.key
        & certz convert test.pem --to pfx --password "AutoPass" --output auto.pfx 2>&1 | Out-Null

        if (Test-Path "auto.pfx") {
            return @{ Success = $true; Details = "Auto-discovered key file" }
        }
        return @{ Success = $false; Details = "Failed with auto-discovery" }
    }

    # conv-3.3: PEM to PFX with generated password
    Invoke-Test -TestId "conv-3.3" -TestName "Convert PEM to PFX with generated password" -TestScript {
        $output = & certz convert test.pem --to pfx --key test.key --output generated.pfx 2>&1

        if ((Test-Path "generated.pfx") -and ($output -match "Password")) {
            return @{ Success = $true; Details = "Password auto-generated and displayed" }
        }
        return @{ Success = $false; Details = "Password generation failed" }
    }

    # ============================================================================
    # PFX TO PEM TESTS
    # ============================================================================

    Write-TestHeader "PFX to PEM Conversion"

    # conv-4.1: Basic PFX to PEM
    Invoke-Test -TestId "conv-4.1" -TestName "Convert PFX to PEM" -TestScript {
        & certz convert test.pfx --to pem --password "TestPass123" --output from-pfx.pem 2>&1 | Out-Null

        $certExists = Test-Path "from-pfx.pem"
        $keyExists = Test-Path "from-pfx.key"

        if ($certExists -and $keyExists) {
            return @{ Success = $true; Details = "PFX split into cert and key files" }
        }
        return @{ Success = $false; Details = "cert=$certExists key=$keyExists" }
    }

    # conv-4.2: PFX to PEM without key
    Invoke-Test -TestId "conv-4.2" -TestName "Convert PFX to PEM without including key" -TestScript {
        & certz convert test.pfx --to pem --password "TestPass123" --output no-key.pem --include-key:$false 2>&1 | Out-Null

        $certExists = Test-Path "no-key.pem"
        $keyExists = Test-Path "no-key.key"

        if ($certExists -and -not $keyExists) {
            return @{ Success = $true; Details = "Certificate only, no key file" }
        }
        return @{ Success = $false; Details = "cert=$certExists key=$keyExists" }
    }

    # ============================================================================
    # PFX TO DER TESTS
    # ============================================================================

    Write-TestHeader "PFX to DER Conversion"

    # conv-5.1: PFX to DER
    Invoke-Test -TestId "conv-5.1" -TestName "Convert PFX to DER" -TestScript {
        & certz convert test.pfx --to der --password "TestPass123" --output from-pfx.der 2>&1 | Out-Null

        if (Test-Path "from-pfx.der") {
            $content = [System.IO.File]::ReadAllBytes("from-pfx.der")
            if ($content[0] -eq 0x30) {
                return @{ Success = $true; Details = "PFX converted to DER" }
            }
            return @{ Success = $false; Details = "Not valid DER format" }
        }
        return @{ Success = $false; Details = "DER file not created" }
    }

    # ============================================================================
    # DER TO PFX TESTS
    # ============================================================================

    Write-TestHeader "DER to PFX Conversion"

    # conv-6.1: DER to PFX (requires separate key)
    Invoke-Test -TestId "conv-6.1" -TestName "Convert DER to PFX with key file" -TestScript {
        & certz convert test.der --to pfx --key test.key --password "DerPfx" --output from-der.pfx 2>&1 | Out-Null

        if (Test-Path "from-der.pfx") {
            return @{ Success = $true; Details = "DER + key converted to PFX" }
        }
        return @{ Success = $false; Details = "PFX file not created" }
    }

    # ============================================================================
    # FORMAT DETECTION TESTS
    # ============================================================================

    Write-TestHeader "Format Detection"

    # conv-7.1: Auto-detect PEM format
    Invoke-Test -TestId "conv-7.1" -TestName "Auto-detect PEM format from .cer extension" -TestScript {
        Copy-Item test.pem test-detect.cer
        $output = & certz convert test-detect.cer --to der --format json 2>&1

        try {
            $json = $output | ConvertFrom-Json
            if ($json.success) {
                return @{ Success = $true; Details = "Detected PEM in .cer file" }
            }
            return @{ Success = $false; Details = "Conversion failed" }
        }
        catch {
            return @{ Success = $false; Details = "Error: $_" }
        }
    }

    # conv-7.2: Auto-detect DER format
    Invoke-Test -TestId "conv-7.2" -TestName "Auto-detect DER format from .cer extension" -TestScript {
        Copy-Item test.der test-detect-binary.cer
        $output = & certz convert test-detect-binary.cer --to pem --output detected.pem --format json 2>&1

        try {
            $json = $output | ConvertFrom-Json
            if ($json.success) {
                return @{ Success = $true; Details = "Detected DER in .cer file" }
            }
            return @{ Success = $false; Details = "Conversion failed" }
        }
        catch {
            return @{ Success = $false; Details = "Error: $_" }
        }
    }

    # conv-7.3: Auto-detect PFX format
    Invoke-Test -TestId "conv-7.3" -TestName "Auto-detect PFX format from .p12 extension" -TestScript {
        Copy-Item test.pfx test-detect.p12
        $output = & certz convert test-detect.p12 --to pem --password "TestPass123" --output from-p12.pem --format json 2>&1

        try {
            $json = $output | ConvertFrom-Json
            if ($json.success) {
                return @{ Success = $true; Details = "Detected PFX/P12 format" }
            }
            return @{ Success = $false; Details = "Conversion failed" }
        }
        catch {
            return @{ Success = $false; Details = "Error: $_" }
        }
    }

    # ============================================================================
    # ERROR HANDLING TESTS
    # ============================================================================

    Write-TestHeader "Error Handling"

    # conv-8.1: Same format error
    Invoke-Test -TestId "conv-8.1" -TestName "Error when input and output formats are same" -TestScript {
        $output = & certz convert test.pem --to pem 2>&1
        $exitCode = $LASTEXITCODE

        if ($exitCode -ne 0 -and ($output -match "same")) {
            return @{ Success = $true; Details = "Correctly rejected same format conversion" }
        }
        return @{ Success = $false; Details = "Expected error for same format" }
    }

    # conv-8.2: Missing password for PFX input
    Invoke-Test -TestId "conv-8.2" -TestName "Error when PFX password missing" -TestScript {
        $output = & certz convert test.pfx --to pem 2>&1
        $exitCode = $LASTEXITCODE

        if ($exitCode -ne 0 -and ($output -match "password" -or $output -match "Password")) {
            return @{ Success = $true; Details = "Correctly required password for PFX" }
        }
        return @{ Success = $false; Details = "Expected password error" }
    }

    # conv-8.3: Missing key for PFX output
    Invoke-Test -TestId "conv-8.3" -TestName "Error when key missing for PFX output" -TestScript {
        # Create a cert-only PEM (no matching key file)
        Copy-Item test.pem orphan.pem
        Remove-Item orphan.key -ErrorAction SilentlyContinue

        $output = & certz convert orphan.pem --to pfx 2>&1
        $exitCode = $LASTEXITCODE

        if ($exitCode -ne 0 -and ($output -match "key" -or $output -match "Key")) {
            return @{ Success = $true; Details = "Correctly required key for PFX" }
        }
        return @{ Success = $false; Details = "Expected key error" }
    }
}
finally {
    Pop-Location
    Remove-TestDirectory $tempDir
}

# ============================================================================
# SUMMARY
# ============================================================================

$exitCode = Write-TestSummary
exit $exitCode
```

**Status:** [ ] Not Started

---

### Step 10: Update Documentation

**Modify:** `README.md`

Add or update the Convert section:

```markdown
## Certificate Format Conversion

Convert certificates between PEM, DER, and PFX formats with automatic format detection.

### Simplified Syntax

```bash
certz convert <input> --to <format> [options]
```

### Examples

```bash
# PFX to PEM (extracts certificate and private key)
certz convert server.pfx --to pem --password secret

# PEM to DER (binary format)
certz convert server.pem --to der

# DER to PEM
certz convert server.der --to pem

# PEM to PFX (auto-discovers server.key)
certz convert server.pem --to pfx

# PEM to PFX with explicit key file
certz convert server.pem --to pfx --key private.key

# Custom output path
certz convert server.pfx --to pem --password secret --output /certs/server.pem

# Certificate only (no private key)
certz convert server.pfx --to pem --password secret --include-key:false
```

### Format Detection

The input format is automatically detected:

| Extension | Detected Format |
|-----------|-----------------|
| .pfx, .p12 | PFX (PKCS#12) |
| .der | DER (binary) |
| .pem | PEM (text) |
| .crt, .cer | Auto-detect from content |

### Options

| Option | Description |
|--------|-------------|
| `--to, -t` | Output format: `pem`, `der`, `pfx` (required) |
| `--output, -o` | Output file path (default: auto-generated) |
| `--key` | Private key file (for PFX output) |
| `--password, -p` | Password for PFX input/output |
| `--password-file` | Read/write password from file |
| `--pfx-encryption` | `modern` (default) or `legacy` |
| `--include-key` | Include private key in output |
| `--format` | Display format: `text`, `json` |

### Legacy Syntax

The original flag-based syntax remains supported:

```bash
# PEM to PFX
certz convert --cert cert.pem --key key.pem --file output.pfx

# PFX to PEM
certz convert --file input.pfx --out-cert cert.pem --out-key key.pem -p secret
```

### Format Reference

| Format | Description | Use Case |
|--------|-------------|----------|
| **PEM** | Base64 text with headers | Web servers, most Linux tools |
| **DER** | Binary ASN.1 encoding | Java keystores, some Windows apps |
| **PFX** | Password-protected bundle | Windows, IIS, certificate export |
```

**Status:** [ ] Not Started

---

## Verification Checklist

### PEM Conversions
- [ ] `certz convert x.pem --to der` creates binary DER file
- [ ] `certz convert x.pem --to pfx --key x.key` creates PFX with key
- [ ] `certz convert x.pem --to pfx` auto-discovers matching .key file

### DER Conversions
- [ ] `certz convert x.der --to pem` creates PEM with headers
- [ ] `certz convert x.der --to pfx --key x.key` creates PFX

### PFX Conversions
- [ ] `certz convert x.pfx --to pem -p secret` extracts cert + key
- [ ] `certz convert x.pfx --to der -p secret` extracts cert as DER
- [ ] `--include-key:false` omits private key from output

### Format Detection
- [ ] .pfx and .p12 detected as PFX
- [ ] .der detected as DER
- [ ] .pem detected as PEM
- [ ] .cer/.crt auto-detected from content

### Error Handling
- [ ] Same format conversion rejected with clear message
- [ ] Missing PFX password returns error
- [ ] Missing key for PFX output returns error
- [ ] Non-existent input file returns error

### Backward Compatibility
- [ ] Legacy `--cert --key --file` syntax still works
- [ ] Legacy `--file --out-cert --out-key` syntax still works

### Output Formats
- [ ] Text output shows conversion details
- [ ] JSON output includes all fields
- [ ] Generated passwords displayed appropriately

---

## Security Considerations

1. **Password handling**: Passwords for PFX files should use `--password-file` in scripts to avoid command-line exposure
2. **Key file permissions**: Generated .key files should have restricted permissions (handled by OS)
3. **Modern encryption**: Default to modern PFX encryption (AES-256-CBC) for new files

---

## Implementation Notes

### Existing Infrastructure

The codebase has these relevant components:
- `ConvertService.cs` - Core conversion logic (extend, don't replace)
- `ConvertCommand.cs` - Current command (add new interface alongside existing)
- `CertificateUtilities.cs` - Helper methods for key handling
- `OptionBuilders.cs` - Standard option creation

### Key .NET APIs for DER Support

```csharp
// Read DER certificate
var cert = new X509Certificate2(derFilePath);

// Write DER certificate
await File.WriteAllBytesAsync(outputPath, certificate.RawData);

// Read DER private key (PKCS#8)
var keyData = await File.ReadAllBytesAsync(keyPath);
var rsa = RSA.Create();
rsa.ImportPkcs8PrivateKey(keyData, out _);

// Write DER private key
var derKey = rsa.ExportPkcs8PrivateKey();
await File.WriteAllBytesAsync(keyPath, derKey);
```

### Backward Compatibility

The existing ConvertCommand logic for legacy flags must remain unchanged. The new simplified interface is additive.
