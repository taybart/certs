# Certool

A tool for dealing with certificates.

![certool](certool.png)

## Table of Contents

[Installation](#installation) 

[Configuration](#configuration) 

[Usage](#usage) 

  * [Generating a Certificate Authority](#generating-a-certificate-authority)
  
  * [Create CSR](#create-csr)
  
  * [Create and sign request](#create-and-sign-request)
  
    * [Output to stdout](#output-to-stdout)
    
  * [Print certificate info](#print-certificate-info)

[Todo](#todo)

# Installation

```
$ go get -u github.com/journeyai/certool/cmd/certool
```

# Configuration

Certool's configuration lives at `$HOME/.config/certool/config.json`
Using `""` as the key will prompt for the password during the command, this is the recommended use.  Setting the password to `_` will not add a password to the ca key. 

```json
{
 "caName": "ca.journey",
 "caKey": "/home/user/.config/certool/ca.journey.key",
 "caCrt": "/home/user/.config/certool/ca.journey.crt",
 "caPassword": ""
}
```

# Usage

```
Usage of certool:
  -c string
        Config file location (default "/home/user/.config/certool")
  -dns string
        DNS for certificate
  -f string
        Certificate file
  -gen
        Generate new CA
  -p    Print certificate contents
  -s string
        Cryptographic scheme for certs [ed25519, rsa2048, rsa4096] (default "ed25519")
  -sign
        sign request
  -w    Write values to file
```

## Generating a Certificate Authority

```
$ certool -s ed25519 -gen
```

## Create CSR

```
$ certool -w -s ed25519 -dns test.denver.journey
```

## Create and sign request

```
$ certool -w -s ed25519 -sign -dns test.denver.journey
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

## Print certificate info

```
$ certool -dns test.denver.journey -sign -w                                                                                                                                                                
$ certool -p -f test.denver.journey.crt    
DNSNames: [test.denver.journey]
Subject: L=Denver,ST=Colorado,C=US
        Issuer: CN=ca.journey,O=Journey,POSTALCODE=80202,STREET=1999 Broadway St,L=Denver,ST=Colorado,C=US
Public Key Algorithm: Ed25519
        Signature f9bfbd407df574773d8a5ed0df7c47ca0dbf3a7349efd2de86883e52b41d7d98e1e86d34783e40082e16891d3dca9d950496e59225ced637cdec65c4248ae20d
```

# Todo

1. Sign certs with yubikey
1. Password protect ca key
1. Pull CA from secret manager
