package main

import (
	"bufio"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/taybart/certs"
)

func main() {
	if err := run(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func run() error {

	if isPiped() {
		// TODO: check for multiple certs being piped and base64 encoded ones
		scanner := bufio.NewScanner(os.Stdin)
		input := ""
		for scanner.Scan() {
			input += scanner.Text() + "\n"
		}
		block, _ := pem.Decode([]byte(input))
		if block == nil {
			return fmt.Errorf("invalid PEM block")
		}
		crt, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return err
		}
		fmt.Println(certs.HumanReadable(crt))
		return nil
	}
	p := os.Args[1]
	if isPath(p) {
		crts, err := certs.LoadCertsFromFile(p)
		if err != nil {
			err = fmt.Errorf("issue loading cert %w", err)
			return err
		}
		for _, crt := range crts {
			fmt.Println(certs.HumanReadable(crt))
		}
		return nil
	}

	chain, err := certs.GetPeerServerCertChain(p)
	if err != nil {
		return fmt.Errorf("issue grabbing remote cert %w", err)
	}
	for _, c := range chain {
		fmt.Println(certs.HumanReadable(c))
	}
	return nil

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
