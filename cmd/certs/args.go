package main

import (
	"github.com/taybart/args"
	"github.com/taybart/certs"
)

var (
	app = args.App{
		Name:    "Certs",
		Version: "v0.0.1",
		About:   "Certificate manager",
		Args: map[string]*args.Arg{
			// CA
			"gen": {
				Help: "Generate a new CA",
				// Default: false,
			},
			// existing
			"config": {
				Short:   "c",
				Help:    "Location of the configuration file",
				Default: certs.DefaultConfig.Dir,
			},
			"profile": {
				Help:    "Profile to use",
				Default: "default",
			},
			"list-profiles": {
				// Short: "l",
				Help:    "List profiles available",
				Default: false,
			},
			"scheme": {
				Short: "s",
				Help:  "Cryptography scheme to use ed25519, ecdsa{256, 384, 512}, rsa{2048, 4096}",
			},
			// certificates
			"signing-request": {
				Short: "csr",
				Help:  "Certificate signing request to sign",
			},
			"hostname": {
				Short: "H",
				Help:  "Generate CSR for provided hostname",
			},
			"sign": {
				Help:    "Also sign the CSR",
				Default: false,
			},

			// Network
			"print": {
				Short: "p",
				Help:  "Print certificate either remote url or local file\n\tex: -p example.com:443 or -p ./example.com.crt",
			},
			"verify": {
				Help: "Test certificate against local valid certificates",
			},
		},
	}
)
