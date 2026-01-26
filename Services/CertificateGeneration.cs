namespace certz.Services;

internal static class CertificateGeneration
{
    private const int RSAMinimumKeySizeInBits = 2048;
    private const string ServerAuthenticationEnhancedKeyUsageOid = "1.3.6.1.5.5.7.3.1";
    private const string ServerAuthenticationEnhancedKeyUsageOidFriendlyName = "Server Authentication";

    internal static X509Certificate2 GenerateCertificate(string[] dnsNames, DateTimeOffset notBefore, DateTimeOffset notAfter)
    {
        var subject = new X500DistinguishedName($"CN={dnsNames[0]}");
        var extensions = new List<X509Extension>();
        var sanBuilder = new SubjectAlternativeNameBuilder();
        foreach (var dnsName in dnsNames)
        {
            if (IPAddress.TryParse(dnsName, out var ipAddress))
            {
                sanBuilder.AddIpAddress(ipAddress);
            }
            else
            {
                sanBuilder.AddDnsName(dnsName);
            }
        }
        var keyUsage = new X509KeyUsageExtension(X509KeyUsageFlags.KeyEncipherment | X509KeyUsageFlags.DigitalSignature, critical: true);
        var enhancedKeyUsage = new X509EnhancedKeyUsageExtension(
            new OidCollection()
            {
                new Oid(ServerAuthenticationEnhancedKeyUsageOid, ServerAuthenticationEnhancedKeyUsageOidFriendlyName)
            }, critical: true);
        var basicConstraints = new X509BasicConstraintsExtension(false, false, 0, true);

        extensions.Add(basicConstraints);
        extensions.Add(keyUsage);
        extensions.Add(enhancedKeyUsage);
        extensions.Add(sanBuilder.Build(true));

        using var key = CreateKeyMaterial(RSAMinimumKeySizeInBits);
        var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        foreach (var extension in extensions)
        {
            request.CertificateExtensions.Add(extension);
        }
        var result = request.CreateSelfSigned(notBefore, notAfter);
        if (OperatingSystem.IsWindows())
        {
            result.FriendlyName = "certz";
        }
        return result;
    }

    private static RSA CreateKeyMaterial(int minimumKeySize)
    {
        var rsa = RSA.Create(minimumKeySize);
        if (rsa.KeySize < minimumKeySize)
        {
            throw new InvalidOperationException($"Failed to create a key with a size of {minimumKeySize} bits");
        }

        return rsa;
    }
}
