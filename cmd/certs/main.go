package main

import (
	"bufio"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/taybart/args"
	"github.com/taybart/certs"
	"github.com/taybart/certs/scheme"
)

var (
	cmd = struct {
		/* CA */
		// new
		Generate bool `arg:"gen"`
		// existing
		Location     string `arg:"config"`
		Profile      string `arg:"profile"`
		ListProfiles bool   `arg:"list-profiles"`
		Scheme       string `arg:"scheme"`
		// certificates
		Hostname string `arg:"hostname"`
		Sign     bool   `arg:"sign"`

		/* Network */
		Print  string `arg:"print"`
		Verify bool   `arg:"verify"`
	}{}
)

func main() {
	if err := run(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func run() error {
	if err := app.Parse(); err != nil {
		if errors.Is(err, args.ErrUsageRequested) {
			return nil
		}
		return err
	}
	if err := app.Marshal(&cmd); err != nil {
		return err
	}

	if cmd.ListProfiles {
		files, err := os.ReadDir(fmt.Sprintf("%s/profiles", cmd.Location))
		if err != nil {
			return err
		}
		for _, f := range files {
			if f.IsDir() {
				fmt.Println(f.Name())
			}
		}
		return nil
	}

	schStr := certs.GetDefaultScheme()
	if cmd.Scheme != "" {
		schStr = cmd.Scheme
	}
	sch, err := scheme.NewScheme(schStr)
	if err != nil {
		return err
	}

	if cmd.Generate {
		if certs.CAExists() {
			reader := bufio.NewReader(os.Stdin)
			fmt.Printf("CA has already been generated, delete and regenerate? [y/N] ")
			val, err := reader.ReadString('\n')
			if err != nil {
				return err
			}
			val = strings.Trim(val, "\n")
			if strings.ToLower(val) != "y" {
				fmt.Println("Not regenerating")
				return nil
			}
		}
		_, err := certs.GenerateCA(sch, cmd.Profile)
		return err
	}

	if cmd.Hostname != "" {
		csr, err := createCSR(cmd.Hostname, sch)
		if err != nil {
			return err
		}
		if cmd.Sign {
			ca, err := certs.LoadCA()
			if err != nil {
				return err
			}
			cert, err := ca.SignRequest(csr.Raw)
			if err != nil {
				return err
			}
			pool := []*x509.Certificate{ca.Cert}
			if err := certs.Verify(cert, pool, cmd.Hostname); err != nil {
				return err
			}
			if err := certs.WriteCertificate(cert); err != nil {
				return err
			}
		}
		return nil
	}

	if cmd.Print != "" {
		if isPath(cmd.Print) {
			crts, err := certs.LoadCertsFromFile(cmd.Print)
			if err != nil {
				err = fmt.Errorf("issue loading cert %w", err)
				return err
			}
			for _, crt := range crts {
				fmt.Println(certs.HumanReadable(crt))
			}
			return nil
		}

		chain, err := certs.GetPeerServerCertChain(cmd.Print)
		if err != nil {
			return fmt.Errorf("issue grabbing remote cert %w", err)
		}
		for _, c := range chain {
			fmt.Println(certs.HumanReadable(c))
		}
		return nil
	}

	app.Usage()

	return nil
}

func createCSR(hostname string, scheme scheme.Scheme) (*x509.CertificateRequest, error) {
	skPem, csr, err := scheme.GenerateDefaultCSR(hostname)
	if err != nil {
		return nil, err
	}
	keyfile := fmt.Sprintf("%s.key", csr.DNSNames[0])
	if err = certs.WritePemToFile(keyfile, skPem); err != nil {
		return nil, err
	}
	if err := certs.WriteCSR(csr); err != nil {
		return nil, err
	}

	return csr, nil
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
