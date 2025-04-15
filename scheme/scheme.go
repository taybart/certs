package scheme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"golang.org/x/term"
)

var (
	noPw           = false
	defaultSubject = Subject{}
)

type Scheme interface {
	String() string
	GenerateKeys() (sk crypto.PrivateKey, pk crypto.PublicKey, err error)
	GenerateDefaultCSR(dns string) (skPem *pem.Block, csr *x509.CertificateRequest, err error)
	GetSignatureAlgorithm() x509.SignatureAlgorithm
	AddCryptoToCSR(csr *x509.CertificateRequest) (skPem *pem.Block, err error)
	PrivateKeyToPem() (skPem *pem.Block, err error)
	MarshalPrivateKeyToFile(dns string) (err error)
}

func NewScheme(s string) (Scheme, error) {
	switch s {
	// FIXME: confirm this is a valid certificate format
	case "curve25519", "ed25519":
		return NewEd25519Scheme(256), fmt.Errorf("use a different scheme")
	case "ecdsa", "ecdsa256":
		return NewECDSAScheme(256), nil
	case "ecdsa384":
		return NewECDSAScheme(384), nil
	case "ecdsa521":
		return NewECDSAScheme(521), nil
	case "rsa1024":
		return NewRSAScheme(1024), nil
	case "rsa", "rsa2048":
		return NewRSAScheme(2048), nil
	case "rsa4096":
		return NewRSAScheme(4096), nil
	default:
		return nil, fmt.Errorf("unknown scheme %s", s)
	}
}

func SchemeFromKey(sk crypto.PrivateKey, pk crypto.PublicKey) (Scheme, error) {
	switch sch := sk.(type) {
	case ed25519.PrivateKey:
		// sch = NewEd25519SchemeFromKeys(sk, pk)
		return nil, fmt.Errorf("use a different scheme")
	case *ecdsa.PrivateKey:
		return NewECDSASchemeFromKeys(sk.(*ecdsa.PrivateKey), pk.(*ecdsa.PublicKey)), nil
	case rsa.PrivateKey:
		return NewRSASchemeFromKeys(sk.(*rsa.PrivateKey), pk.(*rsa.PublicKey)), nil
	default:
		return nil, fmt.Errorf("unknown key scheme %s", sch)
	}
}

func SetDefaultSubject(s Subject) {
	defaultSubject = s
}

func SetNoPw() {
	noPw = true
}
func readPassword() []byte {
	if noPw {
		return nil
	}
	fmt.Printf("Password (enter for no-pw) -> ")
	tty, err := os.Open("/dev/tty") // Use tty just in case stdin is pipe
	if err != nil {
		panic(fmt.Errorf("can't open /dev/tty: %w", err))
	}
	bytePassword, err := term.ReadPassword(int(tty.Fd()))
	if err != nil {
		panic(err)
	}
	fmt.Printf("\n")

	return bytePassword
}
