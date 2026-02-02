using System.Text.Json;
using System.Text.Json.Serialization;
using certz.Models;

namespace certz.Formatters;

// DTO types for JSON serialization
internal record CertificateDto(
    string Subject,
    string Thumbprint,
    string NotBefore,
    string NotAfter,
    string KeyType,
    string[]? SANs,
    bool IsCA,
    int? PathLength
);

internal record CertificateCreatedOutput(
    bool Success,
    CertificateDto Certificate,
    string[]? Files,
    string? Password,
    bool WasTrusted
);

internal record CertificateInspectedOutput(
    bool Success,
    CertificateInspectDto Certificate,
    ChainElementDto[]? Chain,
    bool ChainIsValid,
    string[]? Warnings
);

internal record CertificateInspectDto(
    string Subject,
    string Issuer,
    string Thumbprint,
    string SerialNumber,
    string NotBefore,
    string NotAfter,
    int DaysRemaining,
    string KeyAlgorithm,
    int KeySize,
    string SignatureAlgorithm,
    string[]? SANs,
    string[]? KeyUsages,
    string[]? EnhancedKeyUsages,
    bool IsCa,
    int? PathLengthConstraint,
    bool HasPrivateKey,
    string Source,
    string? SourcePath
);

internal record ChainElementDto(
    string Subject,
    string Issuer,
    string Thumbprint,
    string SerialNumber,
    string NotBefore,
    string NotAfter,
    bool IsCa,
    bool IsSelfSigned,
    string[]? ValidationErrors
);

internal record ErrorOutput(bool Success, string Error);
internal record WarningOutput(string Warning);
internal record SuccessOutput(bool Success, string Message);

// Source generator context for AOT compatibility
[JsonSourceGenerationOptions(
    WriteIndented = true,
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(CertificateCreatedOutput))]
[JsonSerializable(typeof(CertificateInspectedOutput))]
[JsonSerializable(typeof(ErrorOutput))]
[JsonSerializable(typeof(WarningOutput))]
[JsonSerializable(typeof(SuccessOutput))]
internal partial class JsonFormatterContext : JsonSerializerContext
{
}

internal class JsonFormatter : IOutputFormatter
{
    public void WriteCertificateCreated(CertificateCreationResult result)
    {
        var certificate = new CertificateDto(
            result.Subject,
            result.Thumbprint,
            result.NotBefore.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            result.NotAfter.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            result.KeyType,
            result.SANs.Length > 0 ? result.SANs : null,
            result.IsCA,
            result.IsCA && result.PathLength >= 0 ? result.PathLength : null
        );

        var output = new CertificateCreatedOutput(
            Success: true,
            Certificate: certificate,
            Files: result.OutputFiles.Length > 0 ? result.OutputFiles : null,
            Password: result.PasswordWasGenerated ? result.Password : null,
            WasTrusted: result.WasTrusted
        );

        Console.WriteLine(JsonSerializer.Serialize(output, JsonFormatterContext.Default.CertificateCreatedOutput));
    }

    public void WriteCertificateInspected(CertificateInspectResult result)
    {
        var certificate = new CertificateInspectDto(
            result.Subject,
            result.Issuer,
            result.Thumbprint,
            result.SerialNumber,
            result.NotBefore.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            result.NotAfter.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            result.DaysRemaining,
            result.KeyAlgorithm,
            result.KeySize,
            result.SignatureAlgorithm,
            result.SubjectAlternativeNames.Count > 0 ? result.SubjectAlternativeNames.ToArray() : null,
            result.KeyUsages.Count > 0 ? result.KeyUsages.ToArray() : null,
            result.EnhancedKeyUsages.Count > 0 ? result.EnhancedKeyUsages.ToArray() : null,
            result.IsCa,
            result.PathLengthConstraint,
            result.HasPrivateKey,
            result.Source.ToString(),
            result.SourcePath
        );

        ChainElementDto[]? chain = null;
        if (result.Chain != null && result.Chain.Count > 0)
        {
            chain = result.Chain.Select(c => new ChainElementDto(
                c.Subject,
                c.Issuer,
                c.Thumbprint,
                c.SerialNumber,
                c.NotBefore.ToString("yyyy-MM-ddTHH:mm:ssZ"),
                c.NotAfter.ToString("yyyy-MM-ddTHH:mm:ssZ"),
                c.IsCa,
                c.IsSelfSigned,
                c.ValidationErrors.Count > 0 ? c.ValidationErrors.ToArray() : null
            )).ToArray();
        }

        var output = new CertificateInspectedOutput(
            Success: true,
            Certificate: certificate,
            Chain: chain,
            ChainIsValid: result.ChainIsValid,
            Warnings: result.Warnings.Count > 0 ? result.Warnings.ToArray() : null
        );

        Console.WriteLine(JsonSerializer.Serialize(output, JsonFormatterContext.Default.CertificateInspectedOutput));
    }

    public void WriteError(string message)
    {
        var output = new ErrorOutput(Success: false, Error: message);
        Console.WriteLine(JsonSerializer.Serialize(output, JsonFormatterContext.Default.ErrorOutput));
    }

    public void WriteWarning(string message)
    {
        var output = new WarningOutput(Warning: message);
        Console.WriteLine(JsonSerializer.Serialize(output, JsonFormatterContext.Default.WarningOutput));
    }

    public void WriteSuccess(string message)
    {
        var output = new SuccessOutput(Success: true, Message: message);
        Console.WriteLine(JsonSerializer.Serialize(output, JsonFormatterContext.Default.SuccessOutput));
    }
}
