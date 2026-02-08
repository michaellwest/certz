using certz.Models;

namespace certz.Formatters;

internal interface IOutputFormatter
{
    void WriteCertificateCreated(CertificateCreationResult result);
    void WriteCertificateInspected(CertificateInspectResult result);
    void WriteStoreList(StoreListResult result);
    void WriteTrustAdded(TrustOperationResult result);
    void WriteTrustRemoved(TrustOperationResult result);
    void WriteConversionResult(ConversionResult result);
    void WriteExportResult(ExportResult result);
    void WriteVerificationResult(CertificateVerificationResult result);
    void WriteLintResult(LintResult result);
    void WriteMonitorResult(MonitorResult result, bool quietMode);
    void WriteMultipleMatchesWarning(List<X509Certificate2> matchingCerts);
    void WriteError(string message);
    void WriteWarning(string message);
    void WriteSuccess(string message);
}
