package main

import (
	"bufio"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/journeyai/certool"
)

var (
	scheme string
	dns    string
	write  bool
	sign   bool
	genCA  bool
	// ca     bool
	caKey  string
	caCert string
)

func init() {
	flag.BoolVar(&write, "w", false, "Write values to file")
	flag.StringVar(&scheme, "s", "ed25519", "Cryptographic scheme for certs [ed25519, rsa2048, rsa4096]")
	flag.StringVar(&dns, "dns", "", "DNS for certificate")
	// flag.BoolVar(&ca, "ca", false, "become ca")
	flag.BoolVar(&sign, "S", false, "sign request")
	flag.BoolVar(&genCA, "gen", false, "Generate CA with name")
	flag.StringVar(&caKey, "key", "", "DNS for certificate")
	flag.StringVar(&caCert, "crt", "", "DNS for certificate")
}

func main() {
	flag.Parse()
	err := certool.LoadConfig()
	if scheme == "" {
		scheme, err = read("scheme", []string{"ed25519", "rsa2048", "rsa4096"})
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	}
	if scheme != "" && dns == "" {
		dns, err = read("dns", []string{})
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	}
	s, err := certool.NewScheme(scheme)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	_, csrbytes, err := s.GenerateCSR(dns)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	if write {
		err = certool.MarshalCSRToPem(csrbytes)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		s.MarshalPrivateKeyToPem(dns)
	} else {
		fmt.Println(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrbytes})))
	}
	if sign {
		var ca certool.CA
		if genCA {
			ca, err = certool.GenerateCA(scheme)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		} else {
			ca, err = certool.LoadCA()
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		}
		certbytes, err := ca.SignRequest(csrbytes)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		cert, err := x509.ParseCertificate(certbytes)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Printf("%s\n\n", certool.HumanReadable(cert))
		err = certool.Verify([]*x509.Certificate{ca.Cert}, cert, dns)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// fmt.Println(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certbytes})))
	}
}

func read(name string, valid []string) (val string, err error) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("Define %s (%v): ", name, valid)
	val, err = reader.ReadString('\n')
	if err != nil {
		return
	}
	val = strings.TrimSuffix(val, "\n")
	return
}
