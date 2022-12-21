# certz

A simple certificate utility built on .net 7 and compiled to a self-contained exe.


```
Description:
  Certz: A Simple Certificate Utility

Usage:
  certz [command] [options]

Options:
  --version       Show version information
  -?, -h, --help  Show help and usage information

Commands:
  list     Lists all certificates.
  install  Installs a certificate.
  create   Creates a certificate.
```

**Example:** The following lists all the installed certificates from the specified locations.

`certz.exe list --storename root --storelocation localmachine`

**Example:** The following creates a new certificate.

```
certz.exe create --f devcert.pfx --p Password12345 --dns *.devx.local
```

**Example:** The following installs a certificate with the provided password.

```
certz.exe install --f C:\certs\devcert.pfx --p Password12345 --sn root --sl localmachine
```
