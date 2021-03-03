package main

import (
	"bufio"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"regexp"
	"strings"

	"github.com/taybart/certs"
	"github.com/taybart/certs/scheme"
)

var (
	configLocation string
	profileName    string

	sch string

	systemCA  bool
	verify    string
	output    string
	printcert bool

	write bool

	csrhost string

	pipe bool
	nopw bool
	edit bool

	genCA  bool
	signCA bool
	sign   bool
	file   string

	hostportRe = regexp.MustCompile(`([[:alnum:]\-\.]+):([[:digit:]]+)`)
)

func init() {
	flag.StringVar(&configLocation, "c", certs.DefaultConfig.Dir, "Config file location")
	flag.StringVar(&profileName, "profile", "", "Profile name")
	flag.StringVar(&sch, "scheme", "", "Cryptographic scheme for certs [ed25519, ecdsa{256, 384, 512}, rsa{2048, 4096}]")

	flag.StringVar(&verify, "verify", "", "Check cert validity")
	flag.BoolVar(&systemCA, "system", false, "Validate using certs CA")

	flag.StringVar(&output, "p", "", "Print certificate contents")
	flag.BoolVar(&printcert, "cert", false, "Print certs certificate contents")

	flag.BoolVar(&nopw, "no-pw", false, "Don't ask for a password (for pipes)")
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
	if profileName != "" {
		if configLocation != certs.DefaultConfig.Dir {
			return errors.New("Cannot use profile if config locaion is also defined")
		}
		configLocation = fmt.Sprintf("%s/%s", configLocation, profileName)
		if _, err := os.Stat(configLocation); os.IsNotExist(err) {
			return errors.New("Profile does not exist")
		}

		err := certs.LoadConfig(configLocation)
		if err != nil {
			return err
		}

	} else {
		if configLocation == certs.DefaultConfig.Dir {
			err := certs.LoadConfig(configLocation)
			if err != nil {
				return err
			}
		} else {
			err := certs.LoadConfigFromFile(configLocation)
			if err != nil {
				return err
			}
		}
	}

	if nopw || pipe {
		scheme.SetNoPw()
	}

	if printcert {
		cert, err := certs.GetCACert()
		if err != nil {
			return err
		}
		fmt.Println(string(pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})))
		return nil

	}

	if sch == "" {
		sch = certs.GetDefaultScheme()
	}

	if edit {
		return certs.EditConfig()
	}

	if genCA {
		if certs.CAExists() {
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
		_, err := certs.GenerateCA(sch)
		return err
	}

	if csrhost != "" {
		_, err := createCSR()
		return err
	}

	if sign || signCA {
		err := signRequest()
		return err
	}

	if verify != "" {
		if isPath(verify) {
			crts, err := certs.LoadCertificates(verify)
			if err != nil {
				err = fmt.Errorf("Issue loading cert %w", err)
				return err
			}

			for _, crt := range crts {
				fmt.Printf("%s\n\n", certs.HumanReadable(crt))
			}

			var dns string
			if len(crts[0].DNSNames) > 0 {
				dns = crts[0].DNSNames[0] // TODO pick which name to test
			} else if crts[0].Subject.CommonName != "" {
				dns = crts[0].Subject.CommonName
				fmt.Println("WARNING: Using common name for verification, this is not recommended")
			} else {
				return fmt.Errorf("No dns detected in cert")
			}

			intermediates := []*x509.Certificate{}
			if len(crts) > 1 {
				intermediates = crts[1:]
			}

			if systemCA {
				err := certs.VerifySystemRoots(crts[0], intermediates, crts[0].DNSNames[0])
				if err != nil {
					err = fmt.Errorf("Certificate invalid %w", err)
					return err
				}
				fmt.Println("Certificate valid")
				return nil
			}

			ca, err := certs.LoadCA()
			if err != nil {
				err = fmt.Errorf("Issue loading certs ca %w", err)
				return err
			}

			err = certs.Verify(crts[0], append(intermediates, ca.Cert), dns)
			if err != nil {
				err = fmt.Errorf("Certificate invalid %w", err)
				return err
			}
			fmt.Println("Certificate valid")
			return nil
		}

		matches := hostportRe.FindAllStringSubmatch(verify, -1)
		if len(matches) == 0 {
			return fmt.Errorf("Issue parsing remote dns to check")
		}
		host := matches[0][1]
		port := matches[0][2]
		chain, err := certs.GetPeerServerCertificateChain(fmt.Sprintf("%s:%s", host, port))
		if err != nil {
			err = fmt.Errorf("Issue grabbing remote cert %w", err)
			return err
		}

		err = certs.Verify(chain[0], chain[1:], host)
		if err != nil {
			err = fmt.Errorf("Certificate chain invalid %w", err)
			return err
		}

		for _, c := range chain {
			fmt.Printf("%v\n\n", certs.HumanReadable(c))
		}
		fmt.Println("Remote chain valid")

		if systemCA {
			err = certs.VerifySystemRoots(chain[0], chain[1:], host)
			if err != nil {
				err = fmt.Errorf("Certificate invalid %w", err)
				return err
			}
			fmt.Println("System check valid")
			return nil
		}

		ca, err := certs.LoadCA()
		if err != nil {
			err = fmt.Errorf("Issue loading certs ca %w", err)
			return err
		}

		err = certs.Verify(chain[0], []*x509.Certificate{ca.Cert}, host)
		if err != nil {
			err = fmt.Errorf("Certificate invalid %w", err)
			return err
		}
		fmt.Println("Certificate valid")
		return nil
	}

	if output != "" {
		if isPath(output) {
			crts, err := certs.LoadCertificates(output)
			if err != nil {
				err = fmt.Errorf("Issue loading cert %w", err)
				return err
			}
			for _, crt := range crts {
				fmt.Println(certs.HumanReadable(crt))
			}
			return nil
		}

		matches := hostportRe.FindAllStringSubmatch(output, -1)
		if len(matches) == 0 {
			return fmt.Errorf("Issue parsing remote dns to check")
		}
		host := matches[0][1]
		port := matches[0][2]
		chain, err := certs.GetPeerServerCertificateChain(fmt.Sprintf("%s:%s", host, port))
		if err != nil {
			err = fmt.Errorf("Issue grabbing remote cert %w", err)
			return err
		}
		for _, c := range chain {
			fmt.Println(certs.HumanReadable(c))
		}
		return nil
	}
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
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return err
		}
		fmt.Println(certs.HumanReadable(cert))
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

	var skPem *pem.Block
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
		err = certs.MarshalCSRToPem(csr)
		if err != nil {
			return
		}
		err = certs.WritePemToFile(fmt.Sprintf("%s.key", csr.DNSNames[0]), skPem)
		if err != nil {
			return
		}
	} else {
		if pipe {
			err = certs.WritePemToFile(fmt.Sprintf("%s.key", csr.DNSNames[0]), skPem)
			if err != nil {
				return
			}
		} else {
			fmt.Printf("%s", pem.EncodeToMemory(skPem))
		}
		fmt.Printf("%s", pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE REQUEST",
			Bytes: csr.Raw,
		}))
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
		if err != nil {
			panic(err)
		}
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

	ca, err := certs.LoadCA()
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

	err = certs.Verify(cert, []*x509.Certificate{ca.Cert}, csrhost)
	if err != nil {
		return
	}

	if write {
		err = certs.MarshalCertificateToPem(cert)
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
