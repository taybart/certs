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
	configLocation string
	scheme         string
	dns            string
	// caKey     string
	// caCert    string
	file     string
	port     string
	customCA bool
	verify   bool
	remote   bool
	write    bool
	sign     bool
	csr      bool
	genCA    bool
)

func init() {
	flag.StringVar(&configLocation, "c", certool.DefaultConfig.Dir, "Config file location")
	flag.StringVar(&scheme, "s", "ed25519", "Cryptographic scheme for certs [ed25519, rsa2048, rsa4096]")
	flag.StringVar(&dns, "dns", "", "DNS for certificate")
	flag.StringVar(&port, "p", "443", "Port of remote server")
	flag.StringVar(&file, "f", "", "Certificate file")

	// flag.StringVar(&caKey, "key", "", "CA certificate key")
	// flag.StringVar(&caCert, "crt", "", "CA certificate file")

	flag.BoolVar(&verify, "verify", false, "Check cert validity")
	flag.BoolVar(&remote, "remote", false, "Check remote peer cert")
	flag.BoolVar(&customCA, "custom", false, "Validate using certool CA")
	flag.BoolVar(&sign, "sign", false, "sign request")
	flag.BoolVar(&csr, "csr", false, "generate csr")
	flag.BoolVar(&genCA, "gen", false, "Generate new CA")
	flag.BoolVar(&write, "w", false, "Write values to file")
}

func main() {
	flag.Parse()
	err := certool.LoadConfig(configLocation)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	if genCA {
		_, err = certool.GenerateCA(scheme)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	}

	if csr {
		_, err = createCSR()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	}

	if sign {
		err = createSignedCert()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	}

	if verify {
		if remote {
			chain, err := certool.GetPeerServerCertificateChain(fmt.Sprintf("%s:%s", dns, port))
			if err != nil {
				fmt.Println("Issue grabbing remote cert", err)
				os.Exit(1)
			}
			err = certool.Verify(chain[1:], chain[0], dns)
			if err != nil {
				fmt.Println("Certificate invalid", err)
				os.Exit(1)
			}
			fmt.Printf("%v\n\n", certool.HumanReadable(chain[0]))
			fmt.Println("Remote chain valid")
			intermediate := []*x509.Certificate{}
			if len(chain) > 2 {
				intermediate = chain[1 : len(chain)-1]
			}
			err = certool.VerifySystemRoots(chain[0], intermediate, dns)
			if err != nil {
				fmt.Println(certool.HumanReadable(chain[0]))
				fmt.Println("Certificate invalid", err)
				os.Exit(1)
			}
			fmt.Println("System check valid")
			os.Exit(0)

		} else if file == "" {
			fmt.Println("Please add -f [filename]")
			os.Exit(1)
		}

		cert, err := certool.LoadCertificate(file)
		if err != nil {
			fmt.Println("Issue loading cert", err)
			os.Exit(1)
		}
		fmt.Printf("%s\n\n", certool.HumanReadable(cert))
		if customCA {
			ca, err := certool.LoadCA()
			if err != nil {
				fmt.Println("Issue loading certool ca", err)
				os.Exit(1)
			}
			err = certool.Verify([]*x509.Certificate{ca.Cert}, cert, dns)
			if err != nil {
				fmt.Println("Certificate invalid", err)
				os.Exit(1)
			}
		} else {
			err := certool.VerifySystemRoots(cert, nil, dns)
			if err != nil {
				fmt.Println("Certificate invalid", err)
				os.Exit(1)
			}
		}
		fmt.Println("Certificate valid")
		os.Exit(0)
	}

	if remote {
		chain, err := certool.GetPeerServerCertificateChain(fmt.Sprintf("%s:%s", dns, port))
		if err != nil {
			fmt.Println("Issue grabbing remote cert", err)
			os.Exit(1)
		}
		for _, c := range chain {
			fmt.Println(certool.HumanReadable(c))
		}
		os.Exit(0)
	}
	if file != "" {
		cert, err := certool.LoadCertificate(file)
		if err != nil {
			fmt.Println("Issue loading cert", err)
			os.Exit(1)
		}
		fmt.Println(certool.HumanReadable(cert))
	}

}

func createCSR() (csr *x509.CertificateRequest, err error) {
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
func createSignedCert() (err error) {
	csr, err := createCSR()
	if err != nil {
		return
	}

	ca, err := certool.LoadCA()
	if err != nil {
		return
	}

	certbytes, err := ca.SignRequest(csr.Raw)
	if err != nil {
		return
	}
	cert, err := x509.ParseCertificate(certbytes)
	if err != nil {
		return
	}
	err = certool.Verify([]*x509.Certificate{ca.Cert}, cert, dns)
	if err != nil {
		return
	}

	if write {
		certool.MarshalCertificateToPem(cert)
	} else {
		fmt.Println(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certbytes})))
	}
	return
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
