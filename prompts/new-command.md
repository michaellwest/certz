# Prompt: Add New Command

Use this prompt when implementing a new CLI command for certz.

## File Structure

Create the following files for a new `<feature>` command:

```
Commands/<Feature>/<Feature>Command.cs    # Command definition and handler
Services/<Feature>Service.cs              # Business logic
Models/<Feature>Options.cs                # Input parameters
Models/<Feature>Result.cs                 # Output record
test/test-<feature>.ps1                   # Test suite
```

## Implementation Checklist

- [ ] Create command class in `Commands/<Feature>/`
- [ ] Create service class in `Services/`
- [ ] Create options class in `Models/`
- [ ] Create result class in `Models/`
- [ ] Add reusable options to `Options/OptionBuilders.cs` if applicable
- [ ] Update `Program.cs` to register the command
- [ ] Create test file in `test/`
- [ ] Update `README.md` with command documentation
- [ ] Update `CLAUDE.md` Code Map

## Code Templates

### Command Class

```csharp
// Commands/<Feature>/<Feature>Command.cs
using System.CommandLine;

namespace Certz.Commands.<Feature>;

public class <Feature>Command
{
    public static Command Create()
    {
        var command = new Command("<feature>", "Description of command");

        // Add options using OptionBuilders for consistency
        var someOption = OptionBuilders.CreateSomeOption();
        var formatOption = OptionBuilders.CreateFormatOption();

        command.AddOption(someOption);
        command.AddOption(formatOption);

        command.SetAction(async (parseResult) =>
        {
            var format = parseResult.GetValue(formatOption);
            var formatter = FormatterFactory.Create(format);

            var options = new <Feature>Options
            {
                // Map from parseResult
            };

            var result = await <Feature>Service.<Operation>(options);
            formatter.Write<Feature>Result(result);
        });

        return command;
    }
}
```

### Service Class

```csharp
// Services/<Feature>Service.cs
namespace Certz.Services;

public static class <Feature>Service
{
    public static async Task<<Feature>Result> <Operation>(<Feature>Options options)
    {
        // Implementation logic

        return new <Feature>Result
        {
            Success = true,
            // Other properties
        };
    }
}
```

### Options Class

```csharp
// Models/<Feature>Options.cs
namespace Certz.Models;

public class <Feature>Options
{
    public string SomeProperty { get; set; } = string.Empty;
    public int Days { get; set; } = 365;
    // Other input parameters
}
```

### Result Class

```csharp
// Models/<Feature>Result.cs
namespace Certz.Models;

public record <Feature>Result
{
    public bool Success { get; init; }
    public string Message { get; init; } = string.Empty;
    // Other output properties
}
```

## Key Patterns

### Exit Codes in Async Handlers

Use `throw new ArgumentException()` for validation errors (NOT `Environment.ExitCode`):

```csharp
// CORRECT
if (invalidCondition)
{
    throw new ArgumentException("Error message here.");
}

// INCORRECT - won't propagate in async handlers
Environment.ExitCode = 1;
return;
```

### Formatter Integration

Always support `--format` option for JSON output:

```csharp
var format = parseResult.GetValue(formatOption);
var formatter = FormatterFactory.Create(format);
formatter.Write<Feature>Result(result);
```

### Reusable Options

Add common options to `OptionBuilders.cs`:

```csharp
public static Option<string> CreateSomeOption()
{
    return new Option<string>(
        aliases: ["--some", "-s"],
        description: "Description here"
    );
}
```

## Reference Files

- `Commands/Create/CreateDevCommand.cs` - Example command structure
- `Services/CreateService.cs` - Example service pattern
- `Models/DevCertificateOptions.cs` - Example options class
- `Models/CertificateCreationResult.cs` - Example result class
- `Options/OptionBuilders.cs` - Centralized option definitions
- `docs/architecture.md` - Architecture overview
