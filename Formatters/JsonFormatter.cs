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

// Store list DTOs
internal record StoreListOutput(
    bool Success,
    string StoreName,
    string StoreLocation,
    int TotalCount,
    int FilteredCount,
    StoreCertificateDto[] Certificates
);

internal record StoreCertificateDto(
    string Subject,
    string Issuer,
    string Thumbprint,
    string NotBefore,
    string NotAfter,
    int DaysRemaining,
    bool IsExpired,
    bool HasPrivateKey,
    bool IsCa
);

// Trust operation DTOs
internal record TrustOperationOutput(
    bool Success,
    string Operation,
    string StoreName,
    string StoreLocation,
    TrustCertificateDto[] Certificates,
    string? Error
);

internal record TrustCertificateDto(
    string Subject,
    string Thumbprint,
    string NotAfter
);

// Multiple matches warning DTO
internal record MultipleMatchesOutput(
    bool Success,
    string Message,
    int MatchCount,
    TrustCertificateDto[] Certificates
);

// Conversion result DTO
internal record ConversionOutput(
    bool Success,
    string OutputFile,
    string? InputCertificate,
    string? InputKey,
    string? InputPfx,
    string[]? AdditionalOutputFiles,
    string? Subject,
    string? GeneratedPassword,
    bool PasswordWasGenerated
);

// Export result DTO
internal record ExportOutput(
    bool Success,
    string Subject,
    string Issuer,
    string Thumbprint,
    string NotAfter,
    string Source,
    string[] OutputFiles,
    string? GeneratedPassword,
    bool PasswordWasGenerated
);

// Verification result DTO
internal record VerificationOutput(
    bool Success,
    string Subject,
    string Thumbprint,
    VerificationExpirationCheckDto ExpirationCheck,
    VerificationChainCheckDto ChainValidation,
    VerificationTrustCheckDto TrustCheck,
    VerificationRevocationCheckDto? RevocationCheck
);

internal record VerificationExpirationCheckDto(
    bool Passed,
    string NotAfter,
    int DaysRemaining,
    bool IsExpired,
    bool IsNotYetValid,
    bool IsExpiringSoon,
    int WarningThreshold,
    string? Message
);

internal record VerificationChainCheckDto(
    bool Passed,
    string[] ChainElements,
    string[]? Errors
);

internal record VerificationTrustCheckDto(
    bool Passed,
    bool IsTrusted,
    string? RootSubject,
    string? Message
);

internal record VerificationRevocationCheckDto(
    bool Passed,
    bool IsRevoked,
    bool IsOffline,
    string? Message
);

// Source generator context for AOT compatibility
[JsonSourceGenerationOptions(
    WriteIndented = false,
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(CertificateCreatedOutput))]
[JsonSerializable(typeof(CertificateInspectedOutput))]
[JsonSerializable(typeof(StoreListOutput))]
[JsonSerializable(typeof(TrustOperationOutput))]
[JsonSerializable(typeof(MultipleMatchesOutput))]
[JsonSerializable(typeof(ConversionOutput))]
[JsonSerializable(typeof(ExportOutput))]
[JsonSerializable(typeof(VerificationOutput))]
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

    public void WriteStoreList(StoreListResult result)
    {
        var certificates = result.Certificates.Select(c => new StoreCertificateDto(
            c.Subject,
            c.Issuer,
            c.Thumbprint,
            c.NotBefore.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            c.NotAfter.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            c.DaysRemaining,
            c.IsExpired,
            c.HasPrivateKey,
            c.IsCa
        )).ToArray();

        var output = new StoreListOutput(
            Success: true,
            StoreName: result.StoreName,
            StoreLocation: result.StoreLocation,
            TotalCount: result.TotalCount,
            FilteredCount: result.FilteredCount,
            Certificates: certificates
        );

        Console.WriteLine(JsonSerializer.Serialize(output, JsonFormatterContext.Default.StoreListOutput));
    }

    public void WriteTrustAdded(TrustOperationResult result)
    {
        var certificates = result.Certificates.Select(c => new TrustCertificateDto(
            c.Subject,
            c.Thumbprint,
            c.NotAfter.ToString("yyyy-MM-ddTHH:mm:ssZ")
        )).ToArray();

        var output = new TrustOperationOutput(
            Success: result.Success,
            Operation: "add",
            StoreName: result.StoreName,
            StoreLocation: result.StoreLocation,
            Certificates: certificates,
            Error: result.ErrorMessage
        );

        Console.WriteLine(JsonSerializer.Serialize(output, JsonFormatterContext.Default.TrustOperationOutput));
    }

    public void WriteTrustRemoved(TrustOperationResult result)
    {
        var certificates = result.Certificates.Select(c => new TrustCertificateDto(
            c.Subject,
            c.Thumbprint,
            c.NotAfter.ToString("yyyy-MM-ddTHH:mm:ssZ")
        )).ToArray();

        var output = new TrustOperationOutput(
            Success: result.Success,
            Operation: "remove",
            StoreName: result.StoreName,
            StoreLocation: result.StoreLocation,
            Certificates: certificates,
            Error: result.ErrorMessage
        );

        Console.WriteLine(JsonSerializer.Serialize(output, JsonFormatterContext.Default.TrustOperationOutput));
    }

    public void WriteConversionResult(ConversionResult result)
    {
        var output = new ConversionOutput(
            Success: result.Success,
            OutputFile: result.OutputFile,
            InputCertificate: result.InputCertificate,
            InputKey: result.InputKey,
            InputPfx: result.InputPfx,
            AdditionalOutputFiles: result.AdditionalOutputFiles.Length > 0 ? result.AdditionalOutputFiles : null,
            Subject: result.Subject,
            GeneratedPassword: result.PasswordWasGenerated ? result.GeneratedPassword : null,
            PasswordWasGenerated: result.PasswordWasGenerated
        );

        Console.WriteLine(JsonSerializer.Serialize(output, JsonFormatterContext.Default.ConversionOutput));
    }

    public void WriteExportResult(ExportResult result)
    {
        var output = new ExportOutput(
            Success: result.Success,
            Subject: result.Subject,
            Issuer: result.Issuer,
            Thumbprint: result.Thumbprint,
            NotAfter: result.NotAfter.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            Source: result.Source,
            OutputFiles: result.OutputFiles,
            GeneratedPassword: result.PasswordWasGenerated ? result.GeneratedPassword : null,
            PasswordWasGenerated: result.PasswordWasGenerated
        );

        Console.WriteLine(JsonSerializer.Serialize(output, JsonFormatterContext.Default.ExportOutput));
    }

    public void WriteVerificationResult(CertificateVerificationResult result)
    {
        var expirationCheck = new VerificationExpirationCheckDto(
            Passed: result.ExpirationCheck.Passed,
            NotAfter: result.ExpirationCheck.NotAfter.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            DaysRemaining: result.ExpirationCheck.DaysRemaining,
            IsExpired: result.ExpirationCheck.IsExpired,
            IsNotYetValid: result.ExpirationCheck.IsNotYetValid,
            IsExpiringSoon: result.ExpirationCheck.IsExpiringSoon,
            WarningThreshold: result.ExpirationCheck.WarningThreshold,
            Message: result.ExpirationCheck.Message
        );

        var chainValidation = new VerificationChainCheckDto(
            Passed: result.ChainValidation.Passed,
            ChainElements: result.ChainValidation.ChainElements.ToArray(),
            Errors: result.ChainValidation.Errors.Count > 0 ? result.ChainValidation.Errors.ToArray() : null
        );

        var trustCheck = new VerificationTrustCheckDto(
            Passed: result.TrustCheck.Passed,
            IsTrusted: result.TrustCheck.IsTrusted,
            RootSubject: result.TrustCheck.RootSubject,
            Message: result.TrustCheck.Message
        );

        VerificationRevocationCheckDto? revocationCheck = null;
        if (result.RevocationCheck != null)
        {
            revocationCheck = new VerificationRevocationCheckDto(
                Passed: result.RevocationCheck.Passed,
                IsRevoked: result.RevocationCheck.IsRevoked,
                IsOffline: result.RevocationCheck.IsOffline,
                Message: result.RevocationCheck.Message
            );
        }

        var output = new VerificationOutput(
            Success: result.Success,
            Subject: result.Subject,
            Thumbprint: result.Thumbprint,
            ExpirationCheck: expirationCheck,
            ChainValidation: chainValidation,
            TrustCheck: trustCheck,
            RevocationCheck: revocationCheck
        );

        Console.WriteLine(JsonSerializer.Serialize(output, JsonFormatterContext.Default.VerificationOutput));
    }

    public void WriteMultipleMatchesWarning(List<X509Certificate2> matchingCerts)
    {
        var certificates = matchingCerts.Select(c => new TrustCertificateDto(
            c.Subject,
            c.Thumbprint,
            c.NotAfter.ToString("yyyy-MM-ddTHH:mm:ssZ")
        )).ToArray();

        var output = new MultipleMatchesOutput(
            Success: false,
            Message: "Multiple certificates match. Use --force to remove all, or specify a thumbprint for single removal.",
            MatchCount: matchingCerts.Count,
            Certificates: certificates
        );

        Console.WriteLine(JsonSerializer.Serialize(output, JsonFormatterContext.Default.MultipleMatchesOutput));
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
