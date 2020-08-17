# Certool

A tool for dealing with certificates.

![certool](assets/certool.png)

## Table of Contents

[Installation](#installation)

[Configuration](#configuration)

[Usage](#usage)

  * [Generating a Certificate Authority](#generating-a-certificate-authority)

  * [Create CSR](#create-csr)

  * [Create and sign request](#create-and-sign-request)

    * [Output to stdout](#output-to-stdout)

  * [Validate certificate](#validate-certificate)

  * [Validate remote certificate](#validate-remote-certificate)

  * [Print certificate info](#print-certificate-info)

  * [Print remote certificate chain](#print-remote-certificate-chain)

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
 "ca": {
   "name": "ca.journey",
   "key": "/home/user/.config/certool/ca.journey.key",
   "crt": "/home/user/.config/certool/ca.journey.crt",
   "scheme": "ed25519"
  }
}
```

# Usage

```
Usage of certool:
  -c string
        Config file location (default "/home/taylor/.config/certool")
  -csr string
        Generate CSR
  -f string
        File to sign
  -gen
        Generate new CA
  -p string
        Print certificate contents
  -scheme string
        Cryptographic scheme for certs [ed25519, ecdsa{256, 384, 512}, rsa{2048, 4096}] (default "ed25519")
  -sign
        Sign request
  -signca
        Sign request as CA
  -system
        Validate using certool CA
  -verify string
        Check cert validity
  -w    Write values to file
```

## Generating a Certificate Authority

```
$ certool -gen
```

## Create CSR

```
$ certool -w -csr test.denver.journey
```

### From file

```json
{
  "dns_names": ["test.com"],
  "subject": {
    "common_name": "Hello dot com",
    "organizational_unit": ["Engineering"],
    "organization": ["Test inc"],
    "street_address": ["1234 Real St"],
    "postal_code": ["12345"],
    "locality": ["Denver"],
    "province": ["Colorado"],
    "country": ["US"]
  },
  "scheme": "ecdsa256"
}
```

```
$ certool -w -csr ./csr.json
```

## Sign request

```
$ certool -w -sign -f ./test.denver.journey.csr
```

## Create CSR and sign

```
$ certool -csr ./csr.json -pipe | go run ./cmd/certool -sign -w
CA Password (hit enter if unencrypted)
-> ✓
```

## Validate certificate

**System roots**

```
$ certool -verify -system ./test.denver.journey.crt
DNSNames: [test.denver.journey]
SerialNumber: 33402702424818636287940487352184976883

Subject: test.denver.journey
         Journey Engineering
         1999 Broadway St, Denver Colorado

Issuer:  ca.journey
         Journey Engineering
         1999 Broadway St, Denver Colorado

KeyUsage: [DigitalSignature CRLSign]
ExtKeyUsage: [ServerAuth OCSPSigning]

PublicKeyAlgorithm: Ed25519
SignatureAlgorithm: Ed25519

Signature:
      202194762a98b48945cd5cf190fbc300246477c41b8ea4d4c2
      43e0871fcb8bd0087abd167da58640dcd394440b6f45309a35
      4b801ec310b3a8dd10ef8a74c007

Certificate invalid invalid cert x509: certificate signed by unknown authority
exit status 1
```

**Certool CA**

```
$ certool -verify ./test.denver.journey.crt
DNSNames: [test.denver.journey]
SerialNumber: 33402702424818636287940487352184976883

Subject: test.denver.journey
         Journey Engineering
         1999 Broadway St, Denver Colorado

Issuer:  ca.journey
         Journey Engineering
         1999 Broadway St, Denver Colorado

KeyUsage: [CRLSign DigitalSignature]
ExtKeyUsage: [ServerAuth OCSPSigning]

PublicKeyAlgorithm: Ed25519
SignatureAlgorithm: Ed25519

Signature:
      202194762a98b48945cd5cf190fbc300246477c41b8ea4d4c2
      43e0871fcb8bd0087abd167da58640dcd394440b6f45309a35
      4b801ec310b3a8dd10ef8a74c007

Certificate valid
```

## Validate remote certificate

**System roots**

```
$ certool -verify example.com:443
DNSNames: [www.example.org example.com example.edu example.net example.org www.example.com www.example.edu www.example.net]
SerialNumber: 21020869104500376438182461249190639870

Subject: www.example.org
         Internet Corporation for Assigned Names and Numbers Technology
         Los Angeles California

Issuer:  DigiCert SHA2 Secure Server CA
         DigiCert Inc


KeyUsage: [DigitalSignature KeyEncipherment]
ExtKeyUsage: [ServerAuth ClientAuth]

PublicKeyAlgorithm: RSA
SignatureAlgorithm: SHA256-RSA

Signature:
      737085ef4041a76a43d5789c7b5548e6bc6b9986bafb0d038b
      78fe11f029a00ccd69140bc60478b2cef087d5019dc4597a71
      fef06e9ec1a0b0912d1fea3d55c533050ccdc13518b06a6866
      4cbf5621da5bd948b98c3521915ddc75d77a462c2227a66fd3
      3a17ebbebd13c5122673c05da335896afb27d4ddaa74742e37
      e5013ba6d030b083d0a1c4752185b2e5fa670030a2bc53834d
      bfd6a883bbbcd6ed1cb31ef1580382008e9cef90f21a5fa2a3
      06da5dbe9fda5da6e62fde588018d3f1627ba6a39faea86972
      638165ae8283a3b5978a9b2051ff1a3f61401e48d06b38f9e1
      fa17d8774a88e63d36244fef0ab99f70f38327f8cf2a057510
      a18a0a8088cd
OCSPServer: [http://ocsp.digicert.com]

Remote chain valid
System check valid
```

### Output to stdout

Removing `-w` will output results to stdout.

```
$ certool -sign ./test.denver.journey.csr
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
$ certool -sign test.denver.journey -w
$ certool -output ./test.denver.journey.crt
DNSNames: [test.denver.journey]
SerialNumber: 33402702424818636287940487352184976883

Subject: test.denver.journey
         Journey Engineering
         1999 Broadway St, Denver Colorado

Issuer:  ca.journey
         Journey Engineering
         1999 Broadway St, Denver Colorado

KeyUsage: [CRLSign DigitalSignature]
ExtKeyUsage: [ServerAuth OCSPSigning]

PublicKeyAlgorithm: Ed25519
SignatureAlgorithm: Ed25519

Signature:
      202194762a98b48945cd5cf190fbc300246477c41b8ea4d4c2
      43e0871fcb8bd0087abd167da58640dcd394440b6f45309a35
      4b801ec310b3a8dd10ef8a74c007
```

## Print remote certificate chain

```
$ certool -remote example.com:443
DNSNames: [www.example.org example.com example.edu example.net example.org www.example.com www.example.edu www.example.net]
SerialNumber: 21020869104500376438182461249190639870

Subject: www.example.org
         Internet Corporation for Assigned Names and Numbers Technology
         Los Angeles California

Issuer:  DigiCert SHA2 Secure Server CA
         DigiCert Inc


KeyUsage: [DigitalSignature KeyEncipherment]
ExtKeyUsage: [ServerAuth ClientAuth]

PublicKeyAlgorithm: RSA
SignatureAlgorithm: SHA256-RSA

Signature:
      737085ef4041a76a43d5789c7b5548e6bc6b9986bafb0d038b
      78fe11f029a00ccd69140bc60478b2cef087d5019dc4597a71
      fef06e9ec1a0b0912d1fea3d55c533050ccdc13518b06a6866
      4cbf5621da5bd948b98c3521915ddc75d77a462c2227a66fd3
      3a17ebbebd13c5122673c05da335896afb27d4ddaa74742e37
      e5013ba6d030b083d0a1c4752185b2e5fa670030a2bc53834d
      bfd6a883bbbcd6ed1cb31ef1580382008e9cef90f21a5fa2a3
      06da5dbe9fda5da6e62fde588018d3f1627ba6a39faea86972
      638165ae8283a3b5978a9b2051ff1a3f61401e48d06b38f9e1
      fa17d8774a88e63d36244fef0ab99f70f38327f8cf2a057510
      a18a0a8088cd
OCSPServer: [http://ocsp.digicert.com]
DNSNames: []
SerialNumber: 2646203786665923649276728595390119057

Certificate is a CA

Subject: DigiCert SHA2 Secure Server CA
         DigiCert Inc


Issuer:  DigiCert Global Root CA
         DigiCert Inc www.digicert.com


KeyUsage: [DigitalSignature CertSign CRLSign]
ExtKeyUsage: []

PublicKeyAlgorithm: RSA
SignatureAlgorithm: SHA256-RSA

Signature:
      233edf4bd23142a5b67e425c1a44cc69d168b45d4be004216c
      4be26dccb1e0978fa65309cdaa2a65e5394f1e83a56e5c98a2
      2426e6fba1ed93c72e02c64d4abfb042df78dab3a8f96dff21
      855336604c76ceec38dcd65180f0c5d6e5d44d2764ab9bc73e
      71fb4897b8336dc91307ee96a21b1815f65c4c40edb3c2ecff
      71c1e347ffd4b900b43742da20c9ea6e8aee1406ae7da25998
      88a81b6f2df4f2c9145f26cf2c8d7eed37c0a9d539b982bf19
      0cea34af002168f8ad73e2c932da38250b55d39a1df06886ed
      2e4134ef7ca5501dbf3af9d3c1080ce6ed1e8a5825e4b877ad
      2d6ef552ddb4748fab492e9d3b9334281f78ce94eac7bdd3c9
      6d1cde5c32f3
OCSPServer: [http://ocsp.digicert.com]
DNSNames: []
SerialNumber: 10944719598952040374951832963794454346

Certificate is a CA

Subject: DigiCert Global Root CA
         DigiCert Inc www.digicert.com


Issuer:  DigiCert Global Root CA
         DigiCert Inc www.digicert.com


KeyUsage: [CRLSign CertSign DigitalSignature]
ExtKeyUsage: []

PublicKeyAlgorithm: RSA
SignatureAlgorithm: SHA1-RSA

Signature:
      cb9c37aa4813120afadd449c4f52b0f4dfae04f5797908a324
      18fc4b2b84c02db9d5c7fef4c11f58cbb86d9c7a74e79829ab
      11b5e370a0a1cd4c8899938c9170e2ab0f1cbe93a9ff63d5e4
      0760d3a3bf9d5b09f1d58ee353f48e63fa3fa7dbb466df6266
      d6d16e418df22db5ea774a9f9d58e22b59c04023ed2d288245
      3e7954922698e08048a837eff0d6796016deace80ecd6eac44
      17382f49dae1453e2ab93653cf3a5006f72ee8c457496c6121
      18d504ad783c2c3a806ba7ebaf1514e9d889c1b9386ce2916c
      8aff64b977255730c01b24a3e1dce9df477cb5b424080530ec
      2dbd0bbf45bf50b9a9f3eb980112adc888c698345f8d0a3cc6
      e9d595956dde
```

# Todo


- [x] ~Validate and print remote TLS certificates [HTTP/1.1]~

- [ ] Validate and print remote TLS certificates [gRPC & HTTP/2]

- [ ] Sign certs with yubikey

- [ ] Add encrypted and signed audit logs

- [x] ~Password protect ca key~

- [ ] Pull CA from secret manager

- [ ] Store certificates in secret manager

- [ ] Create Kubernetes secrets and/or hook into cert-manager
