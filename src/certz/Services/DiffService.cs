using certz.Models;

namespace certz.Services;

/// <summary>
/// Service for comparing two certificates field by field.
/// </summary>
internal static class DiffService
{
    /// <summary>
    /// Compares two certificates and returns a structured diff result.
    /// </summary>
    public static async Task<DiffResult> CompareCertificatesAsync(DiffOptions options)
    {
        var inspect1Options = new InspectOptions
        {
            Source = options.Source1,
            Password = options.Password1,
            StoreName = options.StoreName1,
            StoreLocation = options.StoreLocation1
        };

        var inspect2Options = new InspectOptions
        {
            Source = options.Source2,
            Password = options.Password2,
            StoreName = options.StoreName2,
            StoreLocation = options.StoreLocation2
        };

        var result1 = await LoadCertificateResult(inspect1Options);
        var result2 = await LoadCertificateResult(inspect2Options);

        var fields = BuildDiffFields(result1, result2);

        return new DiffResult
        {
            Source1 = options.Source1,
            Source2 = options.Source2,
            Fields = fields
        };
    }

    private static async Task<CertificateInspectResult> LoadCertificateResult(InspectOptions options)
    {
        var sourceType = DetectSourceType(options.Source, options.StoreName);

        return sourceType switch
        {
            InspectSource.Url => await CertificateInspector.InspectUrlAsync(options),
            InspectSource.Store => CertificateInspector.InspectFromStore(options),
            InspectSource.File => CertificateInspector.InspectFile(options),
            _ => throw new InvalidOperationException($"Unknown source type for: {options.Source}")
        };
    }

    private static InspectSource DetectSourceType(string source, string? storeName)
    {
        if (source.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            return InspectSource.Url;

        if (!string.IsNullOrEmpty(storeName))
            return InspectSource.Store;

        if (File.Exists(source))
            return InspectSource.File;

        if (IsValidThumbprint(source))
            return InspectSource.Store;

        throw new FileNotFoundException(
            $"File not found: {source}. If this is a thumbprint, use --store to specify the certificate store.");
    }

    private static bool IsValidThumbprint(string value)
    {
        if (string.IsNullOrEmpty(value) || value.Length != 40)
            return false;

        return value.All(c => char.IsAsciiHexDigit(c));
    }

    private static List<CertDiffField> BuildDiffFields(
        CertificateInspectResult left,
        CertificateInspectResult right)
    {
        var fields = new List<CertDiffField>();

        fields.Add(Compare("Subject", left.Subject, right.Subject));
        fields.Add(Compare("Issuer", left.Issuer, right.Issuer));
        fields.Add(Compare("Serial Number", left.SerialNumber, right.SerialNumber));
        fields.Add(Compare("Thumbprint", left.Thumbprint, right.Thumbprint));
        fields.Add(Compare("Valid From",
            left.NotBefore.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss") + " UTC",
            right.NotBefore.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss") + " UTC"));
        fields.Add(Compare("Valid To",
            left.NotAfter.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss") + " UTC",
            right.NotAfter.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss") + " UTC"));
        fields.Add(Compare("Key Algorithm",
            $"{left.KeyAlgorithm} ({left.KeySize} bits)",
            $"{right.KeyAlgorithm} ({right.KeySize} bits)"));
        fields.Add(Compare("Signature Algorithm", left.SignatureAlgorithm, right.SignatureAlgorithm));
        fields.Add(Compare("SANs",
            left.SubjectAlternativeNames.Count > 0 ? string.Join(", ", left.SubjectAlternativeNames) : "(none)",
            right.SubjectAlternativeNames.Count > 0 ? string.Join(", ", right.SubjectAlternativeNames) : "(none)"));
        fields.Add(Compare("Key Usage",
            left.KeyUsages.Count > 0 ? string.Join(", ", left.KeyUsages) : "(none)",
            right.KeyUsages.Count > 0 ? string.Join(", ", right.KeyUsages) : "(none)"));
        fields.Add(Compare("Enhanced Key Usage",
            left.EnhancedKeyUsages.Count > 0 ? string.Join(", ", left.EnhancedKeyUsages) : "(none)",
            right.EnhancedKeyUsages.Count > 0 ? string.Join(", ", right.EnhancedKeyUsages) : "(none)"));
        fields.Add(Compare("Is CA",
            left.IsCa ? "Yes" : "No",
            right.IsCa ? "Yes" : "No"));

        if (left.IsCa || right.IsCa)
        {
            fields.Add(Compare("Path Length",
                left.PathLengthConstraint.HasValue ? left.PathLengthConstraint.Value.ToString() : "(none)",
                right.PathLengthConstraint.HasValue ? right.PathLengthConstraint.Value.ToString() : "(none)"));
        }

        return fields;
    }

    private static CertDiffField Compare(string name, string leftValue, string rightValue)
    {
        var status = string.Equals(leftValue, rightValue, StringComparison.Ordinal)
            ? DiffFieldStatus.Unchanged
            : DiffFieldStatus.Changed;

        return new CertDiffField(name, leftValue, rightValue, status);
    }
}
