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
```

**Example:** The following lists all the installed certificates from the specified locations.

`certz.exe list --storename root --storelocation localmachine`

**Example:** The following installs a root certificate.

`.\certz.exe install --file C:\certs\myrootcert.crt --storename trustedpublisher --storelocation localmachine`
