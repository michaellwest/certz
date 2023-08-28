# certz 🔐

A simple certificate utility built on .net 7 and compiled to a self-contained exe for use with Windows.

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
  export   Exports a certificate.
```

**Example:** The following lists all the installed certificates from the specified locations.

`certz.exe list --storename root --storelocation localmachine`

**Example:** The following creates a new certificate.

```
certz.exe create --f devcert.pfx --p Password12345 --dns *.devx.local
```

**Example:** The following creates PFX and CER certificate files with an expiration of years. The password defaults to **changeit**.

```
certz.exe create --f devcert.pfx --c devcert.cer --k devcert.key --days 1825
```

**Example:** The following installs a certificate with the provided password.

```
certz.exe install --f C:\certs\devcert.pfx --p Password12345 --sn root --sl localmachine
```

**Example:** The following removes a certificate matching the provided thumbprint.

```
certz.exe remove --thumb 94163681942B9B440A22535B3E6BFEA64DE9A3E7 --sn root
```

**Example:** The following downloads a certificate from the provided url.

```
certz.exe export --f devcert-bak.pfx --c devcert-bak.pem --url https://www.github.com
```