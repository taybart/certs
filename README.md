# Certool

![certool](certool.png)

CLI for dealing with certificates

##### Table of Contents
[Installation](#Installation) 

[Configuration](#Configuration) 

[Usage](#Usage) 

  1. [Generating a Certificate Authority](#Generating a Certificate Authority)

## Installation

```
$ go get -u github.com/journeyai/certool/cmd/certool
```

## Configuration

Using `""` as the key will prompt for the password during the command, this is the recommended use.  Setting the password to `_` will not add a password to the ca key. 

```json
{
 "dir": "/Users/taylor/.config/certool",
 "caName": "ca.journey",
 "caKey": "/Users/taylor/.config/certool/ca.journey.key",
 "caCrt": "/Users/taylor/.config/certool/ca.journey.crt",
 "caPassword": "_"
}
```

### Generating a Certificate Authority


### Create CSR

```
$ certool -s ed25519 -sign -dns test.denver.journey -w
```

### Create and sign request

```
$ certool -s ed25519 -sign -dns test.denver.journey -w
```

### Output to stdout

Removing `-w` will output results to stdout.

```
$ certool -s ed25519 -sign -dns test.denver.journey
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIJPb+/pcWV/jbB0UBk6HpDhXVjTzm0ltnbefPxQmfrqi
-----END PRIVATE KEY-----

-----BEGIN CERTIFICATE REQUEST-----
MIHiMIGVAgEAMDExCzAJBgNVBAYTAlVTMREwDwYDVQQIEwhDb2xvcmFkbzEPMA0G
A1UEBxMGRGVudmVyMCowBQYDK2VwAyEAsc5zbIvKOpO9Xcj9+U1TgQLC3jCHsigR
DUEYmBCw9MWgMTAvBgkqhkiG9w0BCQ4xIjAgMB4GA1UdEQQXMBWCE3Rlc3QuZGVu
dmVyLmpvdXJuZXkwBQYDK2VwA0EAHrfnkkoajJyQhZlxZ4JGSkVFuTQwWGoFu5fc
yaClbZ+WXp1ggiPri18xiO/8+xDD6sm5xjRwv9u8sodNlXMbBg==
-----END CERTIFICATE REQUEST-----

-----BEGIN CERTIFICATE-----
MIIBxTCCAXegAwIBAgIRAJgVdYAMHbthuWXBplmyq/QwBQYDK2VwMIGDMQswCQYD
VQQGEwJVUzERMA8GA1UECBMIQ29sb3JhZG8xDzANBgNVBAcTBkRlbnZlcjEZMBcG
A1UECRMQMTk5OSBCcm9hZHdheSBTdDEOMAwGA1UEERMFODAyMDIxEDAOBgNVBAoT
B0pvdXJuZXkxEzARBgNVBAMTCmNhLmpvdXJuZXkwHhcNMjAwNzAzMTcxODUyWhcN
MjEwNzAzMTcxODUyWjAxMQswCQYDVQQGEwJVUzERMA8GA1UECBMIQ29sb3JhZG8x
DzANBgNVBAcTBkRlbnZlcjAqMAUGAytlcAMhALHOc2yLyjqTvV3I/flNU4ECwt4w
h7IoEQ1BGJgQsPTFo1EwTzAOBgNVHQ8BAf8EBAMCAYIwHQYDVR0lBBYwFAYIKwYB
BQUHAwEGCCsGAQUFBwMJMB4GA1UdEQQXMBWCE3Rlc3QuZGVudmVyLmpvdXJuZXkw
BQYDK2VwA0EA8MNcJTGPDDXQ/p4uow6/vwZSfjS6+OgeIAU4AaivJpE20uU2+H8n
MYQBgNVqhkgGEUFIkg5eVpBIHB5x38MLAw==
-----END CERTIFICATE-----

```
