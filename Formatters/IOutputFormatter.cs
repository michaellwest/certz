using certz.Models;

namespace certz.Formatters;

internal interface IOutputFormatter
{
    void WriteCertificateCreated(CertificateCreationResult result);
    void WriteError(string message);
    void WriteWarning(string message);
    void WriteSuccess(string message);
}
