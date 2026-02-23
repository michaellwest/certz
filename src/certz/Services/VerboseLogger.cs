namespace certz.Services;

/// <summary>
/// Ambient static logger for --verbose diagnostic output.
/// All output goes to stderr so it does not contaminate stdout or pipe output.
/// </summary>
internal static class VerboseLogger
{
    private const string Prefix = "[verbose]";

    /// <summary>Gets or sets whether verbose logging is enabled.</summary>
    internal static bool Enabled { get; set; }

    /// <summary>
    /// Writes a verbose diagnostic line to stderr if verbose mode is enabled.
    /// </summary>
    internal static void Log(string message)
    {
        if (!Enabled) return;
        Console.Error.WriteLine($"{Prefix} {message}");
    }

    /// <summary>
    /// Writes full exception details to stderr if verbose mode is enabled.
    /// </summary>
    internal static void LogException(Exception exception)
    {
        if (!Enabled) return;
        Console.Error.WriteLine($"{Prefix} Exception: {exception.GetType().FullName}");
        Console.Error.WriteLine($"{Prefix} Message: {exception.Message}");
        if (exception.StackTrace is not null)
        {
            foreach (var line in exception.StackTrace.Split('\n'))
            {
                Console.Error.WriteLine($"{Prefix}   {line.TrimEnd()}");
            }
        }
        if (exception.InnerException is not null)
        {
            Console.Error.WriteLine($"{Prefix} Inner exception: {exception.InnerException.GetType().FullName}: {exception.InnerException.Message}");
        }
    }
}
