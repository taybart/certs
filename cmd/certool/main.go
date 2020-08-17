package main

import (
	"bufio"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"regexp"
	"strings"

	"github.com/journeyai/certool"
	"github.com/journeyai/certool/scheme"
)

var (
	configLocation string

	sch string

	systemCA bool
	verify   string
	output   string

	write bool

	csrhost string

	pipe bool
	edit bool

	genCA  bool
	signCA bool
	sign   bool
	file   string
)

func init() {
	flag.StringVar(&configLocation, "c", certool.DefaultConfig.Dir, "Config file location")
	flag.StringVar(&sch, "scheme", "ed25519", "Cryptographic scheme for certs [ed25519, ecdsa{256, 384, 512}, rsa{2048, 4096}]")

	flag.StringVar(&verify, "verify", "", "Check cert validity")
	flag.BoolVar(&systemCA, "system", false, "Validate using certool CA")

	flag.StringVar(&output, "p", "", "Print certificate contents")

	flag.BoolVar(&pipe, "pipe", false, "Output will be piped")
	flag.BoolVar(&edit, "edit", false, "Edit the config")

	flag.BoolVar(&genCA, "gen", false, "Generate new CA")
	flag.BoolVar(&signCA, "signca", false, "Sign request as CA")
	flag.BoolVar(&sign, "sign", false, "Sign request")
	flag.StringVar(&file, "f", "", "File to sign")

	flag.StringVar(&csrhost, "csr", "", "Generate CSR")

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

	if edit {
		return certool.EditConfig()
	}

	if genCA {
		if certool.CAExists() {
			reader := bufio.NewReader(os.Stdin)
			fmt.Printf("CA has already been generated, delete and regenerate? [y/N] ")
			val, err := reader.ReadString('\n')
			if err != nil {
				return err
			}
			val = strings.Trim(val, "\n")
			if val != "y" && val != "Y" {
				fmt.Println("Not regenerating")
				return nil
			}
		}
		_, err = certool.GenerateCA(sch)
		return err
	}

	if csrhost != "" {
		_, err = createCSR()
		return err
	}

	if sign || signCA {
		err = signRequest()
		return err
	}

	if verify != "" {
		if isPath(verify) {
			cert, err := certool.LoadCertificate(verify)
			if err != nil {
				err = fmt.Errorf("Issue loading cert %w", err)
				return err
			}
			fmt.Printf("%s\n\n", certool.HumanReadable(cert))

			var dns string
			if len(cert.DNSNames) > 0 {
				dns = cert.DNSNames[0] // TODO pick which name to test
			} else if cert.Subject.CommonName != "" {
				dns = cert.Subject.CommonName
				fmt.Println("WARNING: Using common name for verification, this is not recommended")
			} else {
				return fmt.Errorf("No dns detected in cert")
			}

			if systemCA {
				err := certool.VerifySystemRoots(cert, nil, cert.DNSNames[0])
				if err != nil {
					err = fmt.Errorf("Certificate invalid %w", err)
					return err
				}
				fmt.Println("Certificate valid")
				return nil
			}

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
			fmt.Println("Certificate valid")
			return nil
		}

		re := regexp.MustCompile(`([[:alnum:]\.]+):([[:digit:]]+)`)
		matches := re.FindAllStringSubmatch(verify, -1)
		if err != nil || len(matches) == 0 {
			return fmt.Errorf("Issue parsing remote dns to check")
		}
		host := matches[0][1]
		port := matches[0][2]
		chain, err := certool.GetPeerServerCertificateChain(fmt.Sprintf("%s:%s", host, port))
		if err != nil {
			err = fmt.Errorf("Issue grabbing remote cert %w", err)
			return err
		}

		fmt.Println(host)
		err = certool.Verify(chain[1:], chain[0], host)
		if err != nil {
			err = fmt.Errorf("Certificate chain invalid %w", err)
			return err
		}

		fmt.Printf("%v\n\n", certool.HumanReadable(chain[0]))
		fmt.Println("Remote chain valid")

		if systemCA {
			err = certool.VerifySystemRoots(chain[0], chain[1:], host)
			if err != nil {
				err = fmt.Errorf("Certificate invalid %w", err)
				return err
			}
			fmt.Println("System check valid")
			return nil
		}

		ca, err := certool.LoadCA()
		if err != nil {
			err = fmt.Errorf("Issue loading certool ca %w", err)
			return err
		}

		err = certool.Verify([]*x509.Certificate{ca.Cert}, chain[0], host)
		if err != nil {
			err = fmt.Errorf("Certificate invalid %w", err)
			return err
		}
		fmt.Println("Certificate valid")
		return nil
	}

	if output != "" {
		if isPath(output) {
			cert, err := certool.LoadCertificate(output)
			if err != nil {
				err = fmt.Errorf("Issue loading cert %w", err)
				return err
			}
			fmt.Println(certool.HumanReadable(cert))
			return nil
		}

		re := regexp.MustCompile(`([[:alnum:]\.]+):([[:digit:]]+)`)
		matches := re.FindAllStringSubmatch(output, -1)
		if err != nil || len(matches) == 0 {
			return fmt.Errorf("Issue parsing remote dns to check")
		}
		host := matches[0][1]
		port := matches[0][2]
		chain, err := certool.GetPeerServerCertificateChain(fmt.Sprintf("%s:%s", host, port))
		if err != nil {
			err = fmt.Errorf("Issue grabbing remote cert %w", err)
			return err
		}
		for _, c := range chain {
			fmt.Println(certool.HumanReadable(c))
		}
		return nil
	}
	flag.Usage()
	return nil
}

func createCSR() (csr *x509.CertificateRequest, err error) {
	if csrhost == "" {
		err = fmt.Errorf("No host specified for csr")
		return
	}

	var skPem pem.Block
	if isPath(csrhost) {
		skPem, csr, err = scheme.CSRFromFile(csrhost)
		if err != nil {
			return
		}
	} else {
		if sch == "" {
			sch, err = read("scheme", []string{"ed25519", "ecdsa{256, 384, 512}", "rsa{2048, 4096}"})
			if err != nil {
				return
			}
		}
		var s scheme.Scheme
		s, err = scheme.NewScheme(sch)
		if err != nil {
			return
		}
		skPem, csr, err = s.GenerateDefaultCSR(csrhost)
		if err != nil {
			return
		}
	}

	if write {
		err = certool.MarshalCSRToPem(csr)
		if err != nil {
			return
		}
		certool.WritePemToFile(fmt.Sprintf("%s.key", csr.DNSNames[0]), skPem)
	} else {
		if pipe {
			certool.WritePemToFile(fmt.Sprintf("%s.key", csr.DNSNames[0]), skPem)
		} else {
			fmt.Printf(string(pem.EncodeToMemory(&skPem)))
		}
		fmt.Printf(string(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE REQUEST",
			Bytes: csr.Raw,
		})))
	}
	return
}

func signRequest() (err error) {
	var csr *x509.CertificateRequest
	if isPiped() {
		reader := bufio.NewReader(os.Stdin)
		var output []rune
		for {
			input, _, err := reader.ReadRune()
			if err != nil && err == io.EOF {
				break
			}
			output = append(output, input)
		}
		block, _ := pem.Decode([]byte(string(output)))
		csr, err = x509.ParseCertificateRequest(block.Bytes)
	} else if file != "" {
		var b []byte
		b, err = ioutil.ReadFile(file)
		if err != nil {
			return
		}
		block, _ := pem.Decode(b)
		csr, err = x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			return
		}
	} else {
		csr, err = createCSR()
		if err != nil {
			return
		}
	}

	ca, err := certool.LoadCA()
	if err != nil {
		return
	}
	var certbytes []byte
	if signCA {
		certbytes, err = ca.SignCARequest(csr.Raw)
		if err != nil {
			return
		}
	}

	if sign {
		certbytes, err = ca.SignRequest(csr.Raw)
		if err != nil {
			return
		}
	}

	if certbytes == nil {
		return fmt.Errorf("issue signing request")
	}

	cert, err := x509.ParseCertificate(certbytes)
	if err != nil {
		return
	}

	err = certool.Verify([]*x509.Certificate{ca.Cert}, cert, csrhost)
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

func isPiped() bool {
	info, err := os.Stdin.Stat()
	if err != nil {
		panic(err)
	}

	return info.Mode()&os.ModeCharDevice == 0
}

// isValidUrl tests a string to determine if it is a well-structured url or not.
func isPath(toTest string) bool {
	_, err := os.Stat(toTest)
	return err == nil
}
