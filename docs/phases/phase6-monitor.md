# Phase 6: Certificate Expiration Monitoring

**Status:** Complete
**Created:** 2026-02-08

## Overview

Implement a `certz monitor` command that scans certificate files, URLs, and certificate stores to identify certificates nearing expiration. This enables proactive certificate management and CI/CD pipeline integration.

## Use Cases

### IT Organization
- **CI/CD Integration**: Fail builds when certificates expire within threshold
- **Infrastructure Monitoring**: Feed JSON output to Prometheus/Grafana dashboards
- **Server Inventory**: Weekly scans to maintain certificate inventory
- **Compliance Auditing**: Ensure 90-day renewal lead time

### Individual Developer
- **Local Dev Certificates**: Check dev certs before debugging sessions
- **Personal Projects**: Monitor side project certificates monthly
- **Container Environments**: Health checks for mounted certificate volumes

## Command Specification

```
certz monitor <sources...> [options]

Arguments:
  sources             Files, directories, URLs, or store specs to scan
                      (accepts multiple values)

Options:
  --warn, -w <days>   Warning threshold in days (default: 30)
  --recursive, -r     Scan subdirectories for certificate files
  --store <name>      Certificate store to scan (My, Root, CA)
  --location <loc>    Store location (CurrentUser, LocalMachine)
  --password, -p      Password for PFX files (or use env: CERTZ_PASSWORD)
  --password-map, --pm  File mapping glob patterns to PFX passwords
  --format            Output format: text (default), json
  --quiet, -q         Only output certificates within warning threshold
  --fail-on-warning   Exit with code 1 if any certificates within threshold
  --fail-on-expired   Exit with code 2 if any certificates expired (default)

Exit Codes:
  0 = All certificates valid and outside warning threshold
  1 = Certificates expiring within threshold (with --fail-on-warning)
  2 = Expired certificates found
```

## Design Decisions

| Area | Decision | Rationale |
|------|----------|-----------|
| **Multiple sources** | Accept variadic arguments | Scan files, URLs, stores in one command |
| **Default threshold** | 30 days | Industry standard for certificate renewal |
| **Exit codes** | Semantic exit codes | CI/CD integration (fail on expired/warning) |
| **Password handling** | Option, env var, or password map file | Secure automation; map file supports mixed passwords via glob patterns |
| **Quiet mode** | Filter output to at-risk certs | Reduce noise in monitoring |
| **Store scanning** | Reuse existing StoreListHandler | Consistent with `store list` |

## Progress Tracker

| # | Step | Status | Notes |
|---|------|--------|-------|
| 1 | Create MonitorOptions model | [x] | src/certz/Models/MonitorOptions.cs |
| 2 | Create MonitorResult model | [x] | src/certz/Models/MonitorResult.cs |
| 3 | Create MonitorService | [x] | src/certz/Services/MonitorService.cs |
| 4 | Create MonitorCommand | [x] | src/certz/Commands/Monitor/MonitorCommand.cs |
| 5 | Add TextFormatter output | [x] | src/certz/Formatters/TextFormatter.cs |
| 6 | Add JsonFormatter output | [x] | src/certz/Formatters/JsonFormatter.cs |
| 7 | Add tests | [x] | test/test-monitor.ps1 |
| 8 | Update documentation | [x] | README.md |
| 9 | Add --password-map option | [x] | OptionBuilders.cs, MonitorCommand.cs, MonitorService.cs |
| 10 | Add --password-map tests | [x] | test/test-monitor.ps1 (mon-6.1–6.3, mon-7.1) |
| 11 | Add nanoserver smoke tests | [x] | test/test-nanoserver.cmd (2 new tests) |

---

## Implementation Steps

### Step 1: Create MonitorOptions Model

**Create:** `src/certz/Models/MonitorOptions.cs`

```csharp
namespace certz.Models;

/// <summary>
/// Options for the monitor command.
/// </summary>
internal record MonitorOptions
{
    /// <summary>
    /// Sources to scan (files, directories, URLs).
    /// </summary>
    public required string[] Sources { get; init; }

    /// <summary>
    /// Warning threshold in days.
    /// </summary>
    public int WarnDays { get; init; } = 30;

    /// <summary>
    /// Scan subdirectories recursively.
    /// </summary>
    public bool Recursive { get; init; }

    /// <summary>
    /// Password for PFX files.
    /// </summary>
    public string? Password { get; init; }

    /// <summary>
    /// Certificate store name to scan.
    /// </summary>
    public string? StoreName { get; init; }

    /// <summary>
    /// Store location (CurrentUser, LocalMachine).
    /// </summary>
    public string? StoreLocation { get; init; }

    /// <summary>
    /// Only output certificates within warning threshold.
    /// </summary>
    public bool QuietMode { get; init; }

    /// <summary>
    /// Exit with code 1 if certificates within warning threshold.
    /// </summary>
    public bool FailOnWarning { get; init; }
}
```

---

### Step 2: Create MonitorResult Model

**Create:** `src/certz/Models/MonitorResult.cs`

```csharp
namespace certz.Models;

/// <summary>
/// Result of monitoring certificates for expiration.
/// </summary>
internal record MonitorResult
{
    /// <summary>
    /// Total number of certificates scanned.
    /// </summary>
    public int TotalScanned { get; init; }

    /// <summary>
    /// Number of certificates expiring within threshold.
    /// </summary>
    public int ExpiringCount { get; init; }

    /// <summary>
    /// Number of expired certificates.
    /// </summary>
    public int ExpiredCount { get; init; }

    /// <summary>
    /// Number of valid certificates outside threshold.
    /// </summary>
    public int ValidCount { get; init; }

    /// <summary>
    /// Warning threshold used (in days).
    /// </summary>
    public int WarnThreshold { get; init; }

    /// <summary>
    /// Individual certificate results.
    /// </summary>
    public List<MonitoredCertificate> Certificates { get; init; } = [];

    /// <summary>
    /// Any errors encountered during scanning.
    /// </summary>
    public List<MonitorError> Errors { get; init; } = [];
}

/// <summary>
/// Information about a monitored certificate.
/// </summary>
internal record MonitoredCertificate
{
    /// <summary>
    /// Source of the certificate (file path, URL, store).
    /// </summary>
    public required string Source { get; init; }

    /// <summary>
    /// Certificate subject.
    /// </summary>
    public required string Subject { get; init; }

    /// <summary>
    /// Certificate thumbprint.
    /// </summary>
    public required string Thumbprint { get; init; }

    /// <summary>
    /// Expiration date.
    /// </summary>
    public required DateTime NotAfter { get; init; }

    /// <summary>
    /// Days remaining until expiration.
    /// </summary>
    public int DaysRemaining { get; init; }

    /// <summary>
    /// Status: Valid, Expiring, Expired, NotYetValid.
    /// </summary>
    public required string Status { get; init; }

    /// <summary>
    /// Whether certificate is within warning threshold.
    /// </summary>
    public bool IsWarning { get; init; }
}

/// <summary>
/// Error encountered during monitoring.
/// </summary>
internal record MonitorError
{
    /// <summary>
    /// Source that caused the error.
    /// </summary>
    public required string Source { get; init; }

    /// <summary>
    /// Error message.
    /// </summary>
    public required string Message { get; init; }
}
```

---

### Step 3: Create MonitorService

**Create:** `src/certz/Services/MonitorService.cs`

```csharp
namespace certz.Services;

internal static class MonitorService
{
    public static MonitorResult Monitor(MonitorOptions options)
    {
        var certificates = new List<MonitoredCertificate>();
        var errors = new List<MonitorError>();
        var now = DateTime.Now;

        // Process each source
        foreach (var source in options.Sources)
        {
            try
            {
                if (IsUrl(source))
                {
                    // Fetch certificate from URL
                    var cert = FetchCertificateFromUrl(source);
                    certificates.Add(CreateMonitoredCertificate(cert, source, now, options.WarnDays));
                }
                else if (Directory.Exists(source))
                {
                    // Scan directory for certificate files
                    var files = GetCertificateFiles(source, options.Recursive);
                    foreach (var file in files)
                    {
                        try
                        {
                            var cert = LoadCertificateFromFile(file, options.Password);
                            certificates.Add(CreateMonitoredCertificate(cert, file, now, options.WarnDays));
                        }
                        catch (Exception ex)
                        {
                            errors.Add(new MonitorError { Source = file, Message = ex.Message });
                        }
                    }
                }
                else if (File.Exists(source))
                {
                    // Load single certificate file
                    var cert = LoadCertificateFromFile(source, options.Password);
                    certificates.Add(CreateMonitoredCertificate(cert, source, now, options.WarnDays));
                }
                else
                {
                    errors.Add(new MonitorError { Source = source, Message = "Source not found" });
                }
            }
            catch (Exception ex)
            {
                errors.Add(new MonitorError { Source = source, Message = ex.Message });
            }
        }

        // Scan certificate store if specified
        if (!string.IsNullOrEmpty(options.StoreName))
        {
            var storeCerts = ScanCertificateStore(options.StoreName, options.StoreLocation ?? "CurrentUser");
            foreach (var cert in storeCerts)
            {
                var storeSource = $"store:{options.StoreLocation}\\{options.StoreName}";
                certificates.Add(CreateMonitoredCertificate(cert, storeSource, now, options.WarnDays));
            }
        }

        return new MonitorResult
        {
            TotalScanned = certificates.Count,
            ExpiredCount = certificates.Count(c => c.Status == "Expired"),
            ExpiringCount = certificates.Count(c => c.Status == "Expiring"),
            ValidCount = certificates.Count(c => c.Status == "Valid"),
            WarnThreshold = options.WarnDays,
            Certificates = certificates,
            Errors = errors
        };
    }

    private static MonitoredCertificate CreateMonitoredCertificate(
        X509Certificate2 cert, string source, DateTime now, int warnDays)
    {
        var daysRemaining = (cert.NotAfter - now).Days;
        var status = daysRemaining < 0 ? "Expired"
            : daysRemaining <= warnDays ? "Expiring"
            : cert.NotBefore > now ? "NotYetValid"
            : "Valid";

        return new MonitoredCertificate
        {
            Source = source,
            Subject = cert.Subject,
            Thumbprint = cert.Thumbprint,
            NotAfter = cert.NotAfter,
            DaysRemaining = daysRemaining,
            Status = status,
            IsWarning = status == "Expiring" || status == "Expired"
        };
    }

    private static string[] GetCertificateFiles(string directory, bool recursive)
    {
        var searchOption = recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly;
        var extensions = new[] { "*.pfx", "*.p12", "*.pem", "*.crt", "*.cer" };

        return extensions
            .SelectMany(ext => Directory.GetFiles(directory, ext, searchOption))
            .ToArray();
    }
}
```

---

### Step 4: Create MonitorCommand

**Create:** `src/certz/Commands/Monitor/MonitorCommand.cs`

```csharp
namespace certz.Commands.Monitor;

internal static class MonitorCommand
{
    internal static void AddMonitorCommand(this RootCommand rootCommand)
    {
        var sourcesArgument = new Argument<string[]>("sources")
        {
            Description = "Files, directories, or URLs to scan",
            Arity = ArgumentArity.ZeroOrMore
        };

        var warnOption = new Option<int>("--warn", "-w")
        {
            Description = "Warning threshold in days",
            DefaultValueFactory = _ => 30
        };

        var recursiveOption = new Option<bool>("--recursive", "-r")
        {
            Description = "Scan subdirectories",
            DefaultValueFactory = _ => false
        };

        var passwordOption = OptionBuilders.CreatePasswordOption();

        var storeOption = new Option<string?>("--store", "-s")
        {
            Description = "Certificate store to scan (My, Root, CA)"
        };

        var locationOption = new Option<string?>("--location", "-l")
        {
            Description = "Store location (CurrentUser, LocalMachine)"
        };

        var quietOption = new Option<bool>("--quiet", "-q")
        {
            Description = "Only show certificates within warning threshold",
            DefaultValueFactory = _ => false
        };

        var failOnWarningOption = new Option<bool>("--fail-on-warning")
        {
            Description = "Exit with code 1 if certificates within threshold",
            DefaultValueFactory = _ => false
        };

        var formatOption = OptionBuilders.CreateFormatOption();

        var command = new Command("monitor", "Monitor certificates for expiration")
        {
            sourcesArgument, warnOption, recursiveOption, passwordOption,
            storeOption, locationOption, quietOption, failOnWarningOption, formatOption
        };

        command.SetAction((parseResult) =>
        {
            var sources = parseResult.GetValue(sourcesArgument) ?? [];
            var warnDays = parseResult.GetValue(warnOption);
            var recursive = parseResult.GetValue(recursiveOption);
            var password = parseResult.GetValue(passwordOption);
            var storeName = parseResult.GetValue(storeOption);
            var storeLocation = parseResult.GetValue(locationOption);
            var quiet = parseResult.GetValue(quietOption);
            var failOnWarning = parseResult.GetValue(failOnWarningOption);
            var format = parseResult.GetValue(formatOption) ?? "text";

            // Use environment variable for password if not specified
            password ??= Environment.GetEnvironmentVariable("CERTZ_PASSWORD");

            var options = new MonitorOptions
            {
                Sources = sources,
                WarnDays = warnDays,
                Recursive = recursive,
                Password = password,
                StoreName = storeName,
                StoreLocation = storeLocation,
                QuietMode = quiet,
                FailOnWarning = failOnWarning
            };

            var result = MonitorService.Monitor(options);

            var formatter = FormatterFactory.Create(format);
            formatter.WriteMonitorResult(result, quiet);

            // Determine exit code
            if (result.ExpiredCount > 0)
                return 2;
            if (failOnWarning && result.ExpiringCount > 0)
                return 1;
            return 0;
        });

        rootCommand.Add(command);
    }
}
```

---

### Step 5: Add TextFormatter Output

**Modify:** `src/certz/Formatters/TextFormatter.cs`

```csharp
public void WriteMonitorResult(MonitorResult result, bool quietMode)
{
    // Header
    AnsiConsole.MarkupLine("[bold]Certificate Expiration Monitor[/]");
    AnsiConsole.MarkupLine($"Threshold: [cyan]{result.WarnThreshold} days[/]");
    AnsiConsole.WriteLine();

    // Summary
    var summaryTable = new Table();
    summaryTable.AddColumn("Status");
    summaryTable.AddColumn("Count");
    summaryTable.Border = TableBorder.Rounded;

    summaryTable.AddRow("[green]Valid[/]", result.ValidCount.ToString());
    summaryTable.AddRow("[yellow]Expiring[/]", result.ExpiringCount.ToString());
    summaryTable.AddRow("[red]Expired[/]", result.ExpiredCount.ToString());
    summaryTable.AddRow("[dim]Total[/]", result.TotalScanned.ToString());

    AnsiConsole.Write(summaryTable);
    AnsiConsole.WriteLine();

    // Certificate details
    var certs = quietMode
        ? result.Certificates.Where(c => c.IsWarning)
        : result.Certificates;

    if (certs.Any())
    {
        var table = new Table();
        table.AddColumn("Source");
        table.AddColumn("Subject");
        table.AddColumn("Expires");
        table.AddColumn("Days");
        table.AddColumn("Status");
        table.Border = TableBorder.Rounded;

        foreach (var cert in certs.OrderBy(c => c.DaysRemaining))
        {
            var statusColor = cert.Status switch
            {
                "Expired" => "red",
                "Expiring" => "yellow",
                _ => "green"
            };

            table.AddRow(
                TruncateSource(cert.Source, 30),
                ExtractCN(cert.Subject),
                cert.NotAfter.ToString("yyyy-MM-dd"),
                cert.DaysRemaining.ToString(),
                $"[{statusColor}]{cert.Status}[/]"
            );
        }

        AnsiConsole.Write(table);
    }

    // Errors
    if (result.Errors.Count > 0)
    {
        AnsiConsole.WriteLine();
        AnsiConsole.MarkupLine("[red]Errors:[/]");
        foreach (var error in result.Errors)
        {
            AnsiConsole.MarkupLine($"  [dim]{error.Source}:[/] {error.Message}");
        }
    }
}
```

---

### Step 6: Add JsonFormatter Output

**Modify:** `src/certz/Formatters/JsonFormatter.cs`

Add DTOs and serialization:

```csharp
internal record MonitorOutput(
    bool Success,
    int TotalScanned,
    int ValidCount,
    int ExpiringCount,
    int ExpiredCount,
    int WarnThreshold,
    MonitorCertificateDto[] Certificates,
    MonitorErrorDto[]? Errors
);

internal record MonitorCertificateDto(
    string Source,
    string Subject,
    string Thumbprint,
    string NotAfter,
    int DaysRemaining,
    string Status,
    bool IsWarning
);

internal record MonitorErrorDto(
    string Source,
    string Message
);

public void WriteMonitorResult(MonitorResult result, bool quietMode)
{
    var certs = quietMode
        ? result.Certificates.Where(c => c.IsWarning)
        : result.Certificates;

    var output = new MonitorOutput(
        Success: true,
        TotalScanned: result.TotalScanned,
        ValidCount: result.ValidCount,
        ExpiringCount: result.ExpiringCount,
        ExpiredCount: result.ExpiredCount,
        WarnThreshold: result.WarnThreshold,
        Certificates: certs.Select(c => new MonitorCertificateDto(
            c.Source, c.Subject, c.Thumbprint,
            c.NotAfter.ToString("yyyy-MM-ddTHH:mm:ssZ"),
            c.DaysRemaining, c.Status, c.IsWarning
        )).ToArray(),
        Errors: result.Errors.Count > 0
            ? result.Errors.Select(e => new MonitorErrorDto(e.Source, e.Message)).ToArray()
            : null
    );

    Console.WriteLine(JsonSerializer.Serialize(output, JsonFormatterContext.Default.MonitorOutput));
}
```

---

### Step 7: Add Tests

**Create:** `test/test-monitor.ps1`

Test categories:
- `mon-1.x`: File monitoring (PFX, PEM, directory)
- `mon-2.x`: URL monitoring
- `mon-3.x`: Store monitoring
- `mon-4.x`: Threshold and exit codes
- `mon-5.x`: JSON output

---

### Step 8: Update Documentation

**Modify:** `README.md`

Add monitor command section with examples.

---

## Example Output

### Text Format
```
Certificate Expiration Monitor
Threshold: 30 days

╭────────────┬───────╮
│ Status     │ Count │
├────────────┼───────┤
│ Valid      │ 3     │
│ Expiring   │ 1     │
│ Expired    │ 0     │
│ Total      │ 4     │
╰────────────┴───────╯

╭─────────────────────┬─────────────────┬────────────┬──────┬──────────╮
│ Source              │ Subject         │ Expires    │ Days │ Status   │
├─────────────────────┼─────────────────┼────────────┼──────┼──────────┤
│ ./certs/api.pfx     │ api.company.com │ 2026-03-01 │ 21   │ Expiring │
│ ./certs/web.pfx     │ www.company.com │ 2026-06-15 │ 127  │ Valid    │
│ https://example.com │ example.com     │ 2027-01-01 │ 327  │ Valid    │
╰─────────────────────┴─────────────────┴────────────┴──────┴──────────╯
```

### JSON Format
```json
{
  "success": true,
  "totalScanned": 4,
  "validCount": 3,
  "expiringCount": 1,
  "expiredCount": 0,
  "warnThreshold": 30,
  "certificates": [
    {
      "source": "./certs/api.pfx",
      "subject": "CN=api.company.com",
      "thumbprint": "ABC123...",
      "notAfter": "2026-03-01T00:00:00Z",
      "daysRemaining": 21,
      "status": "Expiring",
      "isWarning": true
    }
  ]
}
```

---

## Verification Checklist

- [ ] `dotnet build` succeeds
- [ ] `certz monitor --help` shows all options
- [ ] File monitoring works (PFX, PEM, CER)
- [ ] Directory scanning works with --recursive
- [ ] URL monitoring works
- [ ] Store monitoring works
- [ ] Warning threshold filters correctly
- [ ] Exit codes work (0, 1 with --fail-on-warning, 2 for expired)
- [ ] JSON output is valid and complete
- [ ] Quiet mode filters output
- [ ] Password from environment variable works
- [ ] Tests pass

---

## Notes & Adjustments

*Record any changes during implementation:*
