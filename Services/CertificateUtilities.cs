using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace certz.Services;

/// <summary>
/// Shared utility methods for certificate operations.
/// </summary>
internal static class CertificateUtilities
{
    /// <summary>
    /// Generates a cryptographically secure random password.
    /// </summary>
    /// <returns>A 64-character hexadecimal string (256 bits of entropy).</returns>
    internal static string GenerateSecurePassword()
    {
        // 32 bytes = 256 bits = 64 hex characters
        byte[] data = RandomNumberGenerator.GetBytes(32);
        return Convert.ToHexString(data);
    }

    /// <summary>
    /// Displays a password warning to the console or writes it to a file.
    /// </summary>
    /// <param name="password">The password to display.</param>
    /// <param name="purpose">Description of what the password is for.</param>
    /// <param name="passwordFile">Optional file to write the password to.</param>
    internal static void DisplayPasswordWarning(string password, string purpose, FileInfo? passwordFile = null)
    {
        if (passwordFile != null)
        {
            passwordFile.Directory?.Create();
            File.WriteAllText(passwordFile.FullName, password.TrimEnd());
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"Password for {purpose} written to: {passwordFile.FullName}");
            Console.ResetColor();
            Console.WriteLine();
            return;
        }

        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("=".PadRight(80, '='));
        Console.WriteLine("IMPORTANT: Certificate Password");
        Console.WriteLine("=".PadRight(80, '='));
        Console.ResetColor();
        Console.WriteLine();
        Console.WriteLine($"Password for {purpose}:");
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine($"  {password}");
        Console.ResetColor();
        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Yellow;
        Console.WriteLine("WARNING: Store this password securely!");
        Console.WriteLine("This is your only chance to see it. Without this password,");
        Console.WriteLine("you will NOT be able to use the certificate.");
        Console.WriteLine("=".PadRight(80, '='));
        Console.ResetColor();
        Console.WriteLine();
    }

    /// <summary>
    /// Gets the appropriate X509 key storage flags based on storage location and options.
    /// </summary>
    /// <param name="storeLocation">Target store location (LocalMachine or CurrentUser).</param>
    /// <param name="persist">Whether to persist the key.</param>
    /// <param name="exportable">Whether the key should be exportable.</param>
    /// <param name="ephemeral">Whether to use ephemeral key storage.</param>
    /// <returns>Configured X509KeyStorageFlags.</returns>
    internal static X509KeyStorageFlags GetKeyStorageFlags(
        StoreLocation? storeLocation = null,
        bool persist = false,
        bool exportable = true,
        bool ephemeral = false)
    {
        if (ephemeral)
        {
            return X509KeyStorageFlags.EphemeralKeySet;
        }

        var flags = (X509KeyStorageFlags)0;

        if (exportable)
            flags |= X509KeyStorageFlags.Exportable;

        if (persist)
            flags |= X509KeyStorageFlags.PersistKeySet;

        // Use MachineKeySet for LocalMachine, UserKeySet for CurrentUser
        // This ensures keys are stored with the correct provider context
        if (storeLocation == StoreLocation.LocalMachine)
            flags |= X509KeyStorageFlags.MachineKeySet;
        else if (storeLocation == StoreLocation.CurrentUser)
            flags |= X509KeyStorageFlags.UserKeySet;

        return flags;
    }
}
