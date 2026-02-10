# Prompt: Add New Command

Use this prompt when implementing a new CLI command for certz.

## File Structure

Create the following files for a new `<feature>` command:

```
src/certz/Commands/<Feature>/<Feature>Command.cs    # Command definition and handler
src/certz/Services/<Feature>Service.cs              # Business logic
src/certz/Models/<Feature>Options.cs                # Input parameters
src/certz/Models/<Feature>Result.cs                 # Output record
test/test-<feature>.ps1                             # Test suite
```

## Implementation Checklist

- [ ] Create command class in `src/certz/Commands/<Feature>/`
- [ ] Create service class in `src/certz/Services/`
- [ ] Create options class in `src/certz/Models/`
- [ ] Create result class in `src/certz/Models/`
- [ ] Add reusable options to `src/certz/Options/OptionBuilders.cs` if applicable
- [ ] Update `src/certz/Program.cs` to register the command
- [ ] Create test file in `test/`
- [ ] Update `README.md` with command documentation
- [ ] Update `CLAUDE.md` Code Map

## Code Templates

### Command Class

```csharp
// src/certz/Commands/<Feature>/<Feature>Command.cs
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
// src/certz/Services/<Feature>Service.cs
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
// src/certz/Models/<Feature>Options.cs
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
// src/certz/Models/<Feature>Result.cs
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

Add common options to `src/certz/Options/OptionBuilders.cs`:

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

- `src/certz/Commands/Create/CreateDevCommand.cs` - Example command structure
- `src/certz/Services/CreateService.cs` - Example service pattern
- `src/certz/Models/DevCertificateOptions.cs` - Example options class
- `src/certz/Models/CertificateCreationResult.cs` - Example result class
- `src/certz/Options/OptionBuilders.cs` - Centralized option definitions
- `docs/architecture.md` - Architecture overview
