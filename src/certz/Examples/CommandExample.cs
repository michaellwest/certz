namespace certz.Examples;

/// <summary>
/// Represents a single command example.
/// </summary>
/// <param name="Description">Brief description of what the example does</param>
/// <param name="Command">The full command to run</param>
/// <param name="Notes">Optional additional notes or explanations</param>
internal record CommandExample(
    string Description,
    string Command,
    string? Notes = null
);
