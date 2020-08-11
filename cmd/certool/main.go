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

	scheme string
	dns    string

	file string
	port string

	systemCA bool
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
	flag.StringVar(&file, "f", "", "Certificate file")

	flag.BoolVar(&remote, "remote", false, "Check remote peer cert")
	flag.StringVar(&port, "p", "443", "Port of remote server")

	flag.BoolVar(&verify, "verify", false, "Check cert validity")
	flag.BoolVar(&systemCA, "system", false, "Validate using certool CA")

	flag.BoolVar(&genCA, "gen", false, "Generate new CA")
	flag.BoolVar(&sign, "sign", false, "sign request")
	flag.BoolVar(&csr, "csr", false, "generate csr")
	flag.BoolVar(&write, "w", false, "Write values to file")
}

func main() {
	flag.Parse()
	if err := run(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func run() error {
	err := certool.LoadConfig(configLocation)
	if err != nil {
		return err
	}

	if genCA {
		if certool.CAExists() {
			reader := bufio.NewReader(os.Stdin)
			fmt.Printf("CA has already been generated, delete and regenerate? [y/N] ")
			val, err := reader.ReadString('\n')
			if err != nil {
				return err
			}
			if val != "y" && val != "Y" {
				fmt.Println("Not regenerating")
				return nil
			}
		}
		_, err = certool.GenerateCA(scheme)
		return err
	}

	if csr {
		_, err = createCSR()
		if err != nil {
			return err
		}
	}

	if sign {
		err = createSignedCert()
		if err != nil {
			return err
		}
	}

	if verify {
		if remote {
			chain, err := certool.GetPeerServerCertificateChain(fmt.Sprintf("%s:%s", dns, port))
			if err != nil {
				err = fmt.Errorf("Issue grabbing remote cert %w", err)
				return err
			}
			err = certool.Verify(chain[1:], chain[0], dns)
			if err != nil {
				err = fmt.Errorf("Certificate invalid %w", err)
				return err
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
				err = fmt.Errorf("Certificate invalid %w", err)
				return err
			}
			fmt.Println("System check valid")
			return err

		} else if file == "" {
			err = fmt.Errorf("Please add -f [filename]")
			return err
		}

		cert, err := certool.LoadCertificate(file)
		if err != nil {
			err = fmt.Errorf("Issue loading cert %w", err)
			return err
		}
		fmt.Printf("%s\n\n", certool.HumanReadable(cert))
		if !systemCA {
			ca, err := certool.LoadCA()
			if err != nil {
				err = fmt.Errorf("Issue loading certool ca %w", err)
				return err
			}
			err = certool.Verify([]*x509.Certificate{ca.Cert}, cert, dns)
			if err != nil {
				err = fmt.Errorf("Certificate invalid %w", err)
				return err
			}
		} else {
			err := certool.VerifySystemRoots(cert, nil, dns)
			if err != nil {
				err = fmt.Errorf("Certificate invalid %w", err)
				return err
			}
		}
		fmt.Println("Certificate valid")
		return nil
	}

	if remote {
		chain, err := certool.GetPeerServerCertificateChain(fmt.Sprintf("%s:%s", dns, port))
		if err != nil {
			err = fmt.Errorf("Issue grabbing remote cert %w", err)
			return err
		}
		for _, c := range chain {
			fmt.Println(certool.HumanReadable(c))
		}
		return nil
	}
	if file != "" {
		cert, err := certool.LoadCertificate(file)
		if err != nil {
			err = fmt.Errorf("Issue loading cert %w", err)
			return err
		}
		fmt.Println(certool.HumanReadable(cert))
	}
	return nil
}

func createCSR() (csr *x509.CertificateRequest, err error) {
	if scheme == "" {
		scheme, err = read("scheme", []string{"ed25519", "rsa2048", "rsa4096"})
		if err != nil {
			return
		}
	}
	s, err := certool.NewScheme(scheme)
	if err != nil {
		return
	}
	sk, _, err := s.GenerateKeys()
	if err != nil {
		return
	}
	csr, err = s.GenerateCSR(dns)
	if err != nil {
		return
	}

	if write {
		err = certool.MarshalCSRToPem(csr.Raw)
		if err != nil {
			return
		}
		err = s.MarshalPrivateKeyToPem(dns)
	} else {
		var skbytes []byte
		skbytes, err = x509.MarshalPKCS8PrivateKey(sk)
		if err != nil {
			return
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
		err = certool.MarshalCertificateToPem(cert)
		if err != nil {
			return
		}
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
