package main

import (
	"bufio"
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
)

func init() {
	flag.StringVar(&scheme, "s", "ed25519", "Cryptographic scheme for certs [ed25519, rsa2048, rsa4096]")
	flag.StringVar(&dns, "dns", "", "DNS for certificate")
	flag.BoolVar(&write, "w", false, "Write values to file")
}

func main() {
	flag.Parse()
	var err error
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
	csr, csrbytes, err := s.GenerateCSR(dns)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	if write {
		fmt.Println("write")
		err = s.MarshalCSRToPem(csr)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		s.MarshalPrivateKeyToPem(dns)
	} else {
		fmt.Println(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrbytes})))
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
