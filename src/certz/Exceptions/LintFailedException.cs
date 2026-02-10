namespace certz.Exceptions;

/// <summary>
/// Exception thrown when lint validation finds errors.
/// This is a "silent" exception that signals the process should exit with code 1
/// but the error message should not be printed (results were already displayed).
/// </summary>
public class LintFailedException : Exception
{
    public LintFailedException() { }

    public LintFailedException(string message) : base(message) { }

    public LintFailedException(string message, Exception inner) : base(message, inner) { }
}
