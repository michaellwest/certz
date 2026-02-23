using certz.Examples;
using certz.Models;

namespace certz.Formatters;

internal interface IOutputFormatter
{
    void WriteDryRunResult(DryRunResult result);
    void WriteDiffResult(DiffResult result);
    void WriteCertificateCreated(CertificateCreationResult result);
    void WriteCertificateInspected(CertificateInspectResult result);
    void WriteStoreList(StoreListResult result);
    void WriteTrustAdded(TrustOperationResult result);
    void WriteTrustRemoved(TrustOperationResult result);
    void WriteConversionResult(ConversionResult result);
    void WriteLintResult(LintResult result);
    void WriteMonitorResult(MonitorResult result, bool quietMode);
    void WriteRenewResult(RenewResult result);
    void WriteMultipleMatchesWarning(List<X509Certificate2> matchingCerts);
    void WriteFingerprintResult(FingerprintResult result);
    void WriteExamples(string commandPath, CommandExample[] examples);
    void WriteAllExamples(IReadOnlyDictionary<string, CommandExample[]> allExamples);
    void WriteError(string message);
    void WriteWarning(string message);
    void WriteSuccess(string message);
}
