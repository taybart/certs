package certool

import (
	"crypto"
	"crypto/x509"
	"fmt"
)

type Scheme interface {
	String() string
	GenerateKeys() (sk crypto.PrivateKey, pk crypto.PublicKey, err error)
	GenerateCSR(dns string) (csr *x509.CertificateRequest, csrbytes []byte, err error)
	MarshalCSRToPem(csr *x509.CertificateRequest) (err error)
	MarshalPrivateKeyToPem(dns string) (err error)
}

func NewScheme(scheme string) (s Scheme, err error) {
	switch scheme {
	case "ed25519":
		s = NewEd25519Scheme(256)
	case "rsa", "rsa2048":
		s = NewRSAScheme(2048)
	case "rsa4096":
		s = NewRSAScheme(4096)
	default:
		err = fmt.Errorf("unknown scheme %s", scheme)
	}
	return
}
