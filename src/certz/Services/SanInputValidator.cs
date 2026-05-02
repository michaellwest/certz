using System.Net;

namespace certz.Services;

/// <summary>
/// Validates SAN dnsName values against the same CA/B Forum rules that the
/// lint command applies (BR-019 whitespace, BR-020 length, BR-021 syntax,
/// BR-023 duplicates). Used by commands that build a SAN list from user
/// input so violations surface as a hard error before the certificate is
/// generated.
/// </summary>
internal static class SanInputValidator
{
    /// <summary>
    /// Throws <see cref="ArgumentException"/> on the first violation found.
    /// Order: per-value checks (BR-019 whitespace, BR-020 length, BR-021 syntax),
    /// then duplicate detection across the full set (BR-023).
    /// IP literals are skipped for syntax/length checks since they belong in
    /// an iPAddress SAN entry rather than a dnsName.
    /// </summary>
    internal static void Validate(IEnumerable<string> sans)
    {
        var values = sans?.ToList() ?? new List<string>();

        foreach (var san in values)
        {
            if (string.IsNullOrEmpty(san))
            {
                throw new ArgumentException("SAN values cannot be empty.");
            }

            // BR-019: whitespace
            if (san.Any(char.IsWhiteSpace))
            {
                throw new ArgumentException(
                    $"SAN value \"{san}\" contains whitespace characters, which are not valid in dnsName values (RFC 5280, BR-019).");
            }

            // IP literals get routed to iPAddress entries by the SAN builder; skip dnsName-only checks.
            if ((san.Contains('.') || san.Contains(':')) && IPAddress.TryParse(san, out _))
            {
                continue;
            }

            var cleaned = san.TrimEnd('.');

            // BR-020: RFC 1035 length limits
            if (cleaned.Length > 253)
            {
                throw new ArgumentException(
                    $"SAN value \"{san}\" exceeds RFC 1035 maximum length of 253 characters (BR-020).");
            }

            var longLabel = cleaned.Split('.').FirstOrDefault(l => l.Length > 63);
            if (longLabel != null)
            {
                throw new ArgumentException(
                    $"SAN value \"{san}\" contains a label of {longLabel.Length} characters, which exceeds RFC 1035 maximum label length of 63 (BR-020).");
            }

            // BR-021: RFC 1035 preferred-name-syntax (LDH, no empty labels, no leading/trailing hyphen; wildcard exempt)
            if (cleaned.Length == 0)
            {
                throw new ArgumentException($"SAN value \"{san}\" is empty after trimming (BR-021).");
            }

            foreach (var label in cleaned.Split('.'))
            {
                if (label.Length == 0)
                {
                    throw new ArgumentException(
                        $"SAN value \"{san}\" contains an empty label, which violates RFC 1035 preferred-name-syntax (BR-021).");
                }
                if (label[0] == '-' || label[^1] == '-')
                {
                    throw new ArgumentException(
                        $"SAN value \"{san}\" has label \"{label}\" that starts or ends with a hyphen, which violates RFC 1035 preferred-name-syntax (BR-021).");
                }
                var badChar = label.FirstOrDefault(c => !(char.IsAsciiLetterOrDigit(c) || c == '-' || c == '*'));
                if (badChar != default(char))
                {
                    throw new ArgumentException(
                        $"SAN value \"{san}\" contains invalid character '{badChar}' in label \"{label}\". Only letters, digits, and hyphens are permitted (BR-021).");
                }
            }
        }

        // BR-023: duplicate SAN values (case-insensitive)
        var duplicate = values
            .GroupBy(s => s, StringComparer.OrdinalIgnoreCase)
            .FirstOrDefault(g => g.Count() > 1);
        if (duplicate != null)
        {
            throw new ArgumentException(
                $"SAN value \"{duplicate.Key}\" appears more than once. Duplicate SANs are not permitted (BR-023).");
        }
    }
}
