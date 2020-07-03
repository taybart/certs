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
	scheme    string
	dns       string
	caKey     string
	caCert    string
	file      string
	write     bool
	sign      bool
	genCA     bool
	printCert bool
)

func init() {
	flag.StringVar(&scheme, "s", "ed25519", "Cryptographic scheme for certs [ed25519, rsa2048, rsa4096]")
	flag.StringVar(&dns, "dns", "", "DNS for certificate")

	flag.StringVar(&caKey, "key", "", "DNS for certificate")
	flag.StringVar(&caCert, "crt", "", "DNS for certificate")
	flag.StringVar(&file, "f", "", "DNS for certificate")

	flag.BoolVar(&printCert, "p", false, "Print certificate contents")
	flag.BoolVar(&sign, "sign", false, "sign request")
	flag.BoolVar(&genCA, "gen", false, "Generate CA with name")
	flag.BoolVar(&write, "w", false, "Write values to file")
}

func main() {
	flag.Parse()
	err := certool.LoadConfig()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	if dns != "" {
		if sign {
			createSignedCert()
		} else {
			createCSR()
		}
	}
	if printCert {
		if file == "" {
			fmt.Println("Please add -f [filename]")
			os.Exit(0)
		}
		cert, err := certool.LoadCertificate(file)
		if err != nil {
			fmt.Println("Issue loading cert", err)
			os.Exit(1)
		}
		fmt.Println(certool.HumanReadable(cert))
	}

}

func createCSR() (csr *x509.CertificateRequest) {
	var err error
	if scheme == "" {
		scheme, err = read("scheme", []string{"ed25519", "rsa2048", "rsa4096"})
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
	sk, _, err := s.GenerateKeys()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	csr, err = s.GenerateCSR(dns)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	if write {
		err = certool.MarshalCSRToPem(csr.Raw)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		s.MarshalPrivateKeyToPem(dns)
	} else {
		skbytes, err := x509.MarshalPKCS8PrivateKey(sk)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Println(string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: skbytes})))
		fmt.Println(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr.Raw})))
	}
	return
}
func createSignedCert() {
	var err error
	csr := createCSR()
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
	certbytes, err := ca.SignRequest(csr.Raw)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	cert, err := x509.ParseCertificate(certbytes)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	err = certool.Verify([]*x509.Certificate{ca.Cert}, cert, dns)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	if write {
		certool.MarshalCertificateToPem(cert)
	} else {
		fmt.Println(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certbytes})))
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
