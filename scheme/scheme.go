package scheme

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

type Scheme interface {
	String() string
	GenerateKeys() (sk crypto.PrivateKey, pk crypto.PublicKey, err error)
	GenerateDefaultCSR(dns string) (skPem pem.Block, csr *x509.CertificateRequest, err error)
	AddCryptoToCSR(csr *x509.CertificateRequest) (skPem pem.Block, err error)
	PrivateKeyToPem() (skPem pem.Block, err error)
	MarshalPrivateKeyToFile(dns string) (err error)
}

func NewScheme(s string) (sch Scheme, err error) {
	switch s {
	case "curve25519", "ed25519":
		sch = NewEd25519Scheme(256)
	case "ecdsa", "ecdsa256":
		sch = NewECDSAScheme(256)
	case "ecdsa384":
		sch = NewECDSAScheme(384)
	case "ecdsa521":
		sch = NewECDSAScheme(521)
	case "rsa1024":
		sch = NewRSAScheme(1024)
	case "rsa", "rsa2048":
		sch = NewRSAScheme(2048)
	case "rsa4096":
		sch = NewRSAScheme(4096)
	default:
		err = fmt.Errorf("unknown scheme %s", sch)
	}
	return
}
