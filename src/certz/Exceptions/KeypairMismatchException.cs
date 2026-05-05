namespace certz.Exceptions;

/// <summary>
/// Thrown when verify-keypair determines the cert/CSR public key does not match the private key.
/// Caught in Program.cs as a silent exit-1 (the result block is already printed by the formatter).
/// </summary>
public class KeypairMismatchException : Exception
{
    public KeypairMismatchException() { }

    public KeypairMismatchException(string message) : base(message) { }

    public KeypairMismatchException(string message, Exception inner) : base(message, inner) { }
}
