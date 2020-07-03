package scheme

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"
)

type Ed25519Scheme struct {
	sk crypto.PrivateKey
	pk crypto.PublicKey
}

func (r Ed25519Scheme) String() string {
	return "ed25519"
}
func NewEd25519Scheme(size int) *Ed25519Scheme {
	return &Ed25519Scheme{}
}

func (e *Ed25519Scheme) GenerateKeys() (sk crypto.PrivateKey, pk crypto.PublicKey, err error) {
	pk, sk, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		err = fmt.Errorf("issue generating ed25519 keys %w", err)
	}
	e.pk = pk
	e.sk = sk
	return sk, pk, err
}

func (e *Ed25519Scheme) GenerateCSR(dns string) (csr *x509.CertificateRequest, err error) {
	if e.sk == nil {
		_, _, err = e.GenerateKeys()
		if err != nil {
			err = fmt.Errorf("issue generating keys for scheme %s %w", e.String(), err)
			return
		}
	}

	csr = &x509.CertificateRequest{
		SignatureAlgorithm: x509.PureEd25519,
		PublicKeyAlgorithm: x509.Ed25519,
		PublicKey:          e.pk,
		Subject: pkix.Name{
			Country:  []string{"US"},
			Province: []string{"Colorado"},
			Locality: []string{"Denver"},
		},
		DNSNames: []string{dns},
	}
	csrbytes, err := x509.CreateCertificateRequest(rand.Reader, csr, e.sk)
	if err != nil {
		err = fmt.Errorf("issue creating csr %w", err)
		return
	}
	csr, err = x509.ParseCertificateRequest(csrbytes)
	if err != nil {
		return
	}
	return
}

func (e Ed25519Scheme) MarshalCSRToPem(csr *x509.CertificateRequest) (err error) {
	if e.sk == nil {
		err = fmt.Errorf("private key is missing from scheme")
		return
	}

	if _, ok := (e.sk).(ed25519.PrivateKey); !ok {
		err = fmt.Errorf("issue with private key format")
		return
	}

	csrbytes, err := x509.CreateCertificateRequest(rand.Reader, csr, e.sk)
	if err != nil {
		err = fmt.Errorf("issue creating csr %w", err)
		return
	}
	out, err := os.OpenFile(csr.DNSNames[0]+".csr", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return
	}
	pem.Encode(out, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrbytes})
	return
}

func (e Ed25519Scheme) MarshalPrivateKeyToPem(dns string) (err error) {
	if e.sk == nil {
		err = fmt.Errorf("private key is missing from scheme")
		return
	}

	if _, ok := (e.sk).(ed25519.PrivateKey); !ok {
		err = fmt.Errorf("issue with private key format")
		return
	}

	keyOut, err := os.OpenFile(dns+".key", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return
	}
	skBytes, err := x509.MarshalPKCS8PrivateKey((e.sk))
	if err != nil {
		return
	}
	pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: skBytes})
	return keyOut.Close()
}
