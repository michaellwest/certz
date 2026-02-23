namespace certz.Exceptions;

/// <summary>
/// Exception thrown when a diff comparison finds differences between two certificates.
/// This is a "silent" exception that signals the process should exit with code 1
/// but the error message should not be printed (diff results were already displayed).
/// </summary>
public class DiffHasDifferencesException : Exception
{
    public DiffHasDifferencesException() { }

    public DiffHasDifferencesException(string message) : base(message) { }

    public DiffHasDifferencesException(string message, Exception inner) : base(message, inner) { }
}
