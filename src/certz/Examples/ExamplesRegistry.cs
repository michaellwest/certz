namespace certz.Examples;

/// <summary>
/// Central registry of command examples for the certz CLI.
/// Examples are organized by command path (e.g., "create dev", "trust add").
/// </summary>
internal static class ExamplesRegistry
{
    private static readonly Dictionary<string, CommandExample[]> _examples = new(StringComparer.OrdinalIgnoreCase)
    {
        // Root / general examples
        [""] =
        [
            new("Launch the interactive wizard", "certz --guided"),
            new("Create a development certificate for localhost", "certz create dev localhost"),
            new("Inspect a certificate file", "certz inspect cert.pfx --password MyPassword"),
            new("Inspect a remote HTTPS certificate", "certz inspect https://github.com"),
            new("Convert PFX to PEM format", "certz convert server.pfx --to pem --password secret"),
            new("Lint a certificate against standards", "certz lint cert.pem"),
        ],

        // create dev examples
        ["create dev"] =
        [
            new("Basic development certificate", "certz create dev localhost"),
            new("Create and auto-trust certificate", "certz create dev api.local --trust"),
            new("With additional Subject Alternative Names", "certz create dev myapp.local --san \"*.myapp.local\" --san \"127.0.0.1\""),
            new("Signed by your own CA", "certz create dev api.local --issuer-cert ca.pfx --issuer-password CaPassword"),
            new("Interactive wizard mode", "certz create dev localhost --guided"),
            new("Output to specific files", "certz create dev localhost --file server.pfx --cert server.cer --key server.key"),
            new("Save generated password to file", "certz create dev localhost --password-file localhost.password"),
            new("Use RSA 4096-bit instead of default ECDSA", "certz create dev api.local --key-type RSA --key-size 4096"),
            new("Ephemeral certificate (in-memory only)", "certz create dev example.com --ephemeral"),
            new("Pipe certificate to stdout", "certz create dev example.com --pipe"),
        ],

        // create ca examples
        ["create ca"] =
        [
            new("Create a Root CA", "certz create ca --name \"Development Root CA\""),
            new("Create and trust the CA", "certz create ca --name \"Dev CA\" --trust"),
            new("With specific validity and path length", "certz create ca --name \"My CA\" --days 3650 --path-length 1"),
            new("With CRL and OCSP URLs", "certz create ca --name \"My CA\" --crl-url http://crl.example.com/ca.crl --ocsp-url http://ocsp.example.com"),
            new("Save generated password to file", "certz create ca --name \"Dev CA\" --password-file ca.password"),
            new("Use ECDSA P-256 key", "certz create ca --name \"Dev CA\" --key-type ECDSA-P256"),
            new("Ephemeral CA for testing (in-memory only)", "certz create ca --name \"Test CA\" --ephemeral"),
            new("Interactive wizard mode", "certz create ca --guided"),
        ],

        // inspect examples
        ["inspect"] =
        [
            new("Inspect a local file", "certz inspect cert.pfx --password MyPassword"),
            new("Inspect remote HTTPS certificate", "certz inspect https://github.com"),
            new("Show certificate chain", "certz inspect https://github.com --chain"),
            new("Detailed chain tree with key info", "certz inspect https://github.com --chain --tree"),
            new("Check revocation status", "certz inspect https://github.com --chain --crl"),
            new("Inspect from certificate store", "certz inspect ABC123DEF456 --store Root --location LocalMachine"),
            new("Save certificate to file", "certz inspect https://github.com --save github.cer"),
            new("JSON output for automation", "certz inspect cert.pfx --password Pass --format json"),
        ],

        // trust add examples
        ["trust add"] =
        [
            new("Add to Root store (CurrentUser)", "certz trust add ca.cer --store Root"),
            new("Add PFX to trust store", "certz trust add cert.pfx --password MyPassword --store Root"),
            new("Add to LocalMachine (requires admin)", "certz trust add ca.cer --store Root --location LocalMachine"),
        ],

        // trust remove examples
        ["trust remove"] =
        [
            new("Remove by full thumbprint", "certz trust remove ABC123DEF456789012345678901234567890ABCD --force"),
            new("Remove by partial thumbprint (8+ chars)", "certz trust remove ABC123DE --force"),
            new("Remove by subject pattern", "certz trust remove --subject \"CN=dev*\" --force"),
            new("Interactive removal (prompts)", "certz trust remove ABC123DEF456"),
        ],

        // convert examples
        ["convert"] =
        [
            new("PFX to PEM (extracts cert + key)", "certz convert server.pfx --to pem --password secret"),
            new("PFX to PEM with private key included", "certz convert server.pfx --to pem --password secret --include-key"),
            new("PEM to DER (binary format)", "certz convert server.pem --to der"),
            new("DER to PEM", "certz convert server.der --to pem"),
            new("PEM to PFX (auto-discovers key)", "certz convert server.pem --to pfx"),
            new("PEM to PFX with explicit key file", "certz convert server.pem --to pfx --key private.key"),
            new("Convert to PFX with password saved to file", "certz convert server.pem --to pfx --password-file output.password"),
            new("Custom output path", "certz convert server.pfx --to pem --password secret --output /certs/server.pem"),
        ],

        // lint examples
        ["lint"] =
        [
            new("Lint a certificate file", "certz lint cert.pfx --password MyPassword"),
            new("Lint with Mozilla NSS policy", "certz lint cert.pem --policy mozilla"),
            new("Lint with relaxed development policy", "certz lint cert.pem --policy dev"),
            new("Lint a remote certificate", "certz lint https://example.com"),
            new("Lint certificate from store by thumbprint", "certz lint ABC123DE --store My --location CurrentUser"),
            new("Show only errors", "certz lint cert.pfx --password Pass --severity error"),
            new("JSON output for CI/CD", "certz lint cert.pfx --password Pass --format json"),
        ],

        // monitor examples
        ["monitor"] =
        [
            new("Monitor certificates in a directory", "certz monitor ./certs"),
            new("Monitor multiple sources", "certz monitor ./certs https://example.com"),
            new("Scan certificate store for expiring certs", "certz monitor --store My --location CurrentUser --warn 30"),
            new("Scan LocalMachine Root store", "certz monitor --store Root --location LocalMachine"),
            new("Scan directory recursively", "certz monitor ./certs --recursive"),
            new("Set expiration warning threshold", "certz monitor ./certs --warn 60"),
            new("CI/CD: exit code 1 if any expiring", "certz monitor ./certs --fail-on-warning"),
            new("Show only warnings (quiet mode)", "certz monitor ./certs --quiet"),
            new("Use password map for mixed passwords", "certz monitor ./certs --password-map passwords.txt"),
            new("JSON output for CI/CD", "certz monitor ./certs --format json"),
        ],

        // renew examples
        ["renew"] =
        [
            new("Renew a certificate", "certz renew server.pfx --password OldPass"),
            new("Renew with new validity period", "certz renew server.pfx --password Pass --days 365"),
            new("Renew preserving existing private key", "certz renew server.pfx --password Pass --keep-key"),
            new("Renew with a different output password", "certz renew server.pfx --password OldPass --out-password NewPass"),
            new("Renew certificate from store by thumbprint", "certz renew ABC123DE --store My --days 90"),
            new("Renew with new output file", "certz renew server.pfx --password Pass --output renewed.pfx"),
        ],

        // store list examples
        ["store list"] =
        [
            new("List certificates in My store", "certz store list"),
            new("List certificates in Root store", "certz store list --store Root"),
            new("List from LocalMachine", "certz store list --store Root --location LocalMachine"),
            new("Show only expired certificates", "certz store list --expired"),
            new("Show expiring within 30 days", "certz store list --expiring 30"),
            new("Expiring certs as JSON for automation", "certz store list --store My --expiring 60 --format json"),
        ],

        // diff examples
        ["diff"] =
        [
            new("Compare two certificate files", "certz diff old.pem new.pem"),
            new("Compare PFX files with password", "certz diff old.pfx new.pfx --password mypass"),
            new("Output differences as JSON", "certz diff cert1.pem cert2.pem --format json"),
        ],

        // fingerprint examples
        ["fingerprint"] =
        [
            new("Print SHA-256 fingerprint", "certz fingerprint cert.pem"),
            new("Fingerprint with no separator", "certz fingerprint cert.pem --no-separator"),
            new("SHA-1 fingerprint for legacy systems", "certz fingerprint cert.pem --algorithm sha1"),
        ],
    };

    /// <summary>
    /// Gets examples for a specific command path.
    /// </summary>
    /// <param name="commandPath">The command path (e.g., "create dev", "trust add"). Use empty string for root.</param>
    /// <returns>Array of examples, or empty array if none found.</returns>
    internal static IReadOnlyDictionary<string, CommandExample[]> GetExamples(string commandPath)
    {
        var key = commandPath.Trim();
        if (_examples.TryGetValue(key, out var examples))
        {
            return new Dictionary<string, CommandExample[]> { [key] = examples };
        }

        var partialMatches = _examples.Where(p => !string.IsNullOrEmpty(p.Key) &&
            (
                p.Key.StartsWith(commandPath, StringComparison.OrdinalIgnoreCase) ||
                commandPath.StartsWith(p.Key, StringComparison.OrdinalIgnoreCase))
            ).ToDictionary();
        return partialMatches.Any() ? partialMatches : [];
    }

    /// <summary>
    /// Gets all registered command paths.
    /// </summary>
    internal static IEnumerable<string> GetAllCommandPaths()
    {
        return _examples.Keys.Where(k => !string.IsNullOrEmpty(k)).OrderBy(k => k);
    }

    /// <summary>
    /// Gets all examples (for "certz examples" with no arguments).
    /// </summary>
    internal static IReadOnlyDictionary<string, CommandExample[]> GetAllExamples()
    {
        return _examples;
    }

    /// <summary>
    /// Checks if examples exist for a command path.
    /// </summary>
    internal static bool HasExamples(string commandPath)
    {
        return _examples.ContainsKey(commandPath.Trim());
    }
}
