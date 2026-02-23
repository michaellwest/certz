using System.Text.Json;
using System.Text.Json.Serialization;
using certz.Examples;
using certz.Models;

namespace certz.Formatters;

// Dry-run result DTOs
internal record DryRunDetailDto(string Key, string Value);

internal record DryRunOutput(
    bool DryRun,
    bool WouldSucceed,
    string Command,
    string Action,
    DryRunDetailDto[] Details
);

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
    bool WasTrusted,
    bool IsEphemeral,
    bool WasPiped
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
    string? KeyAlgorithm,
    int KeySize,
    string? SignatureAlgorithm,
    string[]? SubjectAlternativeNames,
    int DaysRemaining,
    string? RevocationStatus,
    string[]? CrlDistributionPoints,
    string? OcspResponder,
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
    string? OutputFormat,
    string? InputCertificate,
    string? InputKey,
    string? InputPfx,
    string[]? AdditionalOutputFiles,
    string? Subject,
    string? GeneratedPassword,
    bool PasswordWasGenerated
);

// Lint result DTOs
internal record LintOutput(
    bool Success,
    bool Passed,
    string Subject,
    string Thumbprint,
    string PolicySet,
    bool IsCa,
    bool IsRoot,
    string? SourcePath,
    int ErrorCount,
    int WarningCount,
    int InfoCount,
    LintFindingDto[] Findings
);

internal record LintFindingDto(
    string RuleId,
    string RuleName,
    string Severity,
    string Message,
    string Policy,
    string? ActualValue,
    string? ExpectedValue
);

// Monitor result DTOs
internal record MonitorOutput(
    bool Success,
    int TotalScanned,
    int ValidCount,
    int ExpiringCount,
    int ExpiredCount,
    int SkippedCount,
    int WarnThreshold,
    MonitorCertificateDto[] Certificates,
    MonitorWarningDto[]? Warnings,
    MonitorErrorDto[]? Errors
);

internal record MonitorCertificateDto(
    string Source,
    string Subject,
    string Thumbprint,
    string NotAfter,
    int DaysRemaining,
    string Status,
    bool IsWarning
);

internal record MonitorWarningDto(
    string Source,
    string Reason
);

internal record MonitorErrorDto(
    string Source,
    string Message
);

// Renew result DTO
internal record RenewOutput(
    bool Success,
    string? Error,
    string OriginalSubject,
    string OriginalThumbprint,
    string OriginalNotAfter,
    string? NewSubject,
    string? NewThumbprint,
    string? NewNotBefore,
    string? NewNotAfter,
    string? OutputFile,
    string? Password,
    bool PasswordWasGenerated,
    string[]? SANs,
    string? KeyType,
    bool KeyWasPreserved,
    bool WasResigned
);

// Fingerprint result DTO
internal record FingerprintOutput(
    bool Success,
    string Algorithm,
    string Fingerprint,
    string Source,
    string Subject
);

// Diff result DTOs
internal record CertDiffFieldDto(
    string Name,
    string LeftValue,
    string RightValue,
    string Status);

internal record DiffOutput(
    bool Success,
    bool AreIdentical,
    int DifferenceCount,
    string Source1,
    string Source2,
    CertDiffFieldDto[] Fields);

// Examples DTOs
internal record ExampleDto(
    string Description,
    string Command,
    string? Notes
);

internal record ExamplesOutput(
    bool Success,
    string? CommandPath,
    ExampleDto[] Examples
);

internal record AllExamplesOutput(
    bool Success,
    Dictionary<string, ExampleDto[]> Commands
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
[JsonSerializable(typeof(LintOutput))]
[JsonSerializable(typeof(MonitorOutput))]
[JsonSerializable(typeof(RenewOutput))]
[JsonSerializable(typeof(ErrorOutput))]
[JsonSerializable(typeof(WarningOutput))]
[JsonSerializable(typeof(SuccessOutput))]
[JsonSerializable(typeof(FingerprintOutput))]
[JsonSerializable(typeof(ExamplesOutput))]
[JsonSerializable(typeof(AllExamplesOutput))]
[JsonSerializable(typeof(DryRunOutput))]
[JsonSerializable(typeof(DiffOutput))]
internal partial class JsonFormatterContext : JsonSerializerContext
{
}

internal class JsonFormatter : IOutputFormatter
{
    public void WriteDryRunResult(DryRunResult result)
    {
        var details = result.Details.Select(d => new DryRunDetailDto(d.Key, d.Value)).ToArray();
        var output = new DryRunOutput(
            DryRun: true,
            WouldSucceed: result.WouldSucceed,
            Command: result.Command,
            Action: result.Action,
            Details: details
        );
        Console.WriteLine(JsonSerializer.Serialize(output, JsonFormatterContext.Default.DryRunOutput));
    }

    public void WriteDiffResult(DiffResult result)
    {
        var fields = result.Fields.Select(f => new CertDiffFieldDto(
            f.Name,
            f.LeftValue,
            f.RightValue,
            f.Status.ToString().ToLowerInvariant()
        )).ToArray();

        var output = new DiffOutput(
            Success: true,
            AreIdentical: result.AreIdentical,
            DifferenceCount: result.DifferenceCount,
            Source1: result.Source1,
            Source2: result.Source2,
            Fields: fields
        );

        Console.WriteLine(JsonSerializer.Serialize(output, JsonFormatterContext.Default.DiffOutput));
    }

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
            WasTrusted: result.WasTrusted,
            IsEphemeral: result.IsEphemeral,
            WasPiped: result.WasPiped
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
                c.KeyAlgorithm,
                c.KeySize,
                c.SignatureAlgorithm,
                c.SubjectAlternativeNames.Count > 0 ? c.SubjectAlternativeNames.ToArray() : null,
                c.DaysRemaining,
                c.RevocationStatus,
                c.CrlDistributionPoints.Count > 0 ? c.CrlDistributionPoints.ToArray() : null,
                c.OcspResponder,
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
            OutputFormat: result.OutputFormat,
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

    public void WriteLintResult(LintResult result)
    {
        var findings = result.Findings.Select(f => new LintFindingDto(
            f.RuleId,
            f.RuleName,
            f.Severity.ToString(),
            f.Message,
            f.Policy,
            f.ActualValue,
            f.ExpectedValue
        )).ToArray();

        var output = new LintOutput(
            Success: true,
            Passed: result.Passed,
            Subject: result.Subject,
            Thumbprint: result.Thumbprint,
            PolicySet: result.PolicySet,
            IsCa: result.IsCa,
            IsRoot: result.IsRoot,
            SourcePath: result.SourcePath,
            ErrorCount: result.ErrorCount,
            WarningCount: result.WarningCount,
            InfoCount: result.InfoCount,
            Findings: findings
        );

        Console.WriteLine(JsonSerializer.Serialize(output, JsonFormatterContext.Default.LintOutput));
    }

    public void WriteMonitorResult(MonitorResult result, bool quietMode)
    {
        var certs = quietMode
            ? result.Certificates.Where(c => c.IsWarning)
            : result.Certificates;

        var certificates = certs.Select(c => new MonitorCertificateDto(
            c.Source,
            c.Subject,
            c.Thumbprint,
            c.NotAfter.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            c.DaysRemaining,
            c.Status,
            c.IsWarning
        )).ToArray();

        var warnings = result.Warnings.Count > 0
            ? result.Warnings.Select(w => new MonitorWarningDto(w.Source, w.Reason)).ToArray()
            : null;

        var errors = result.Errors.Count > 0
            ? result.Errors.Select(e => new MonitorErrorDto(e.Source, e.Message)).ToArray()
            : null;

        var output = new MonitorOutput(
            Success: true,
            TotalScanned: result.TotalScanned,
            ValidCount: result.ValidCount,
            ExpiringCount: result.ExpiringCount,
            ExpiredCount: result.ExpiredCount,
            SkippedCount: result.SkippedCount,
            WarnThreshold: result.WarnThreshold,
            Certificates: certificates,
            Warnings: warnings,
            Errors: errors
        );

        Console.WriteLine(JsonSerializer.Serialize(output, JsonFormatterContext.Default.MonitorOutput));
    }

    public void WriteRenewResult(RenewResult result)
    {
        var output = new RenewOutput(
            Success: result.Success,
            Error: result.ErrorMessage,
            OriginalSubject: result.OriginalSubject,
            OriginalThumbprint: result.OriginalThumbprint,
            OriginalNotAfter: result.OriginalNotAfter.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            NewSubject: result.NewSubject,
            NewThumbprint: result.NewThumbprint,
            NewNotBefore: result.NewNotBefore?.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            NewNotAfter: result.NewNotAfter?.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            OutputFile: result.OutputFile,
            Password: result.PasswordWasGenerated ? result.Password : null,
            PasswordWasGenerated: result.PasswordWasGenerated,
            SANs: result.SANs?.Length > 0 ? result.SANs : null,
            KeyType: result.KeyType,
            KeyWasPreserved: result.KeyWasPreserved,
            WasResigned: result.WasResigned
        );

        Console.WriteLine(JsonSerializer.Serialize(output, JsonFormatterContext.Default.RenewOutput));
    }

    public void WriteFingerprintResult(Models.FingerprintResult result)
    {
        var output = new FingerprintOutput(
            Success: true,
            Algorithm: result.Algorithm,
            Fingerprint: result.Fingerprint,
            Source: result.Source,
            Subject: result.Subject
        );
        Console.WriteLine(JsonSerializer.Serialize(output, JsonFormatterContext.Default.FingerprintOutput));
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

    public void WriteExamplesIndex(IReadOnlyDictionary<string, CommandExample[]> allExamples)
    {
        WriteAllExamples(allExamples);
    }

    public void WriteExamples(string commandPath, CommandExample[] examples)
    {
        var exampleDtos = examples.Select(e => new ExampleDto(e.Description, e.Command, e.Notes)).ToArray();
        var output = new ExamplesOutput(
            Success: true,
            CommandPath: string.IsNullOrEmpty(commandPath) ? null : commandPath,
            Examples: exampleDtos
        );
        Console.WriteLine(JsonSerializer.Serialize(output, JsonFormatterContext.Default.ExamplesOutput));
    }

    public void WriteAllExamples(IReadOnlyDictionary<string, CommandExample[]> allExamples)
    {
        var commands = allExamples.ToDictionary(
            kvp => string.IsNullOrEmpty(kvp.Key) ? "general" : kvp.Key,
            kvp => kvp.Value.Select(e => new ExampleDto(e.Description, e.Command, e.Notes)).ToArray()
        );
        var output = new AllExamplesOutput(Success: true, Commands: commands);
        Console.WriteLine(JsonSerializer.Serialize(output, JsonFormatterContext.Default.AllExamplesOutput));
    }
}
