package scheme

import (
	"crypto"
	"crypto/x509"
)

type Scheme interface {
	String() string
	GenerateKeys() (sk crypto.PrivateKey, pk crypto.PublicKey, err error)
	GenerateCSR(dns string) (csr *x509.CertificateRequest, err error)
	MarshalCSRToPem(csr *x509.CertificateRequest) (err error)
	MarshalPrivateKeyToPem(dns string) (err error)
}
