# Certool

CLI for dealing with certificates

## Installation

```
$ go get -u github.com/journeyai/certool/cmd/cli
```

## CSR

```
$ certool -s ed25519 -dns test.denver.journey
-----BEGIN CERTIFICATE REQUEST-----
MIHTMIGGAgEAMDExCzAJBgNVBAYTAlVTMREwDwYDVQQIEwhDb2xvcmFkbzEPMA0G
A1UEBxMGRGVudmVyMCowBQYDK2VwAyEA+FZ9BcOwo0EfVLOc2r06w0ZC6tPOvKt7
1Uc7Mk+hMVOgIjAgBgkqhkiG9w0BCQ4xEzARMA8GA1UdEQQIMAaCBHRlc3QwBQYD
K2VwA0EACFgjthUKPiCo57sCWLgGO+li/DaiGoRJSPB5JjWtgQzkQ4gthv9BX6mB
rtijQu3rYWkOBorTyp5ReHbKyrNZAA==
-----END CERTIFICATE REQUEST-----
```
