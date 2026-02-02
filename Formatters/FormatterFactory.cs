namespace certz.Formatters;

internal static class FormatterFactory
{
    public static IOutputFormatter Create(string format)
    {
        return format.ToLowerInvariant() switch
        {
            "json" => new JsonFormatter(),
            "text" or "" or null => new TextFormatter(),
            _ => throw new ArgumentException($"Unknown output format: {format}. Valid formats are: text, json")
        };
    }
}
