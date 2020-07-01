package certool

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"
)

type RSAScheme struct {
	size int
	sk   crypto.PrivateKey
	pk   crypto.PublicKey
}

func NewRSAScheme(size int) *RSAScheme {
	return &RSAScheme{
		size: size,
	}
}

func (r RSAScheme) String() string {
	return fmt.Sprintf("rsa%d", r.size)
}

func (r *RSAScheme) GenerateKeys() (sk crypto.PrivateKey, pk crypto.PublicKey, err error) {
	rsask, err := rsa.GenerateKey(rand.Reader, r.size)
	if err != nil {
		return
	}
	r.sk = rsask
	r.pk = rsask.PublicKey
	return rsask, rsask.PublicKey, nil
}

func (r *RSAScheme) GenerateCSR(dns string) (csr *x509.CertificateRequest, csrbytes []byte, err error) {
	sk, pk, err := r.GenerateKeys()
	if err != nil {
		err = fmt.Errorf("issue generating keys for scheme %s %w", r.String(), err)
		return
	}
	csr = &x509.CertificateRequest{
		SignatureAlgorithm: x509.SHA256WithRSA,
		PublicKeyAlgorithm: x509.RSA,
		PublicKey:          pk.(rsa.PublicKey),
		Subject: pkix.Name{
			Country:  []string{"US"},
			Province: []string{"Colorado"},
			Locality: []string{"Denver"},
		},
		DNSNames: []string{dns},
	}
	csrbytes, err = x509.CreateCertificateRequest(rand.Reader, csr, sk.(*rsa.PrivateKey))
	if err != nil {
		err = fmt.Errorf("issue creating csr %w", err)
		return
	}
	csr, err = x509.ParseCertificateRequest(csrbytes)
	if err != nil {
		return
	}

	// csrPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
	return
}

func (r RSAScheme) MarshalCSRToPem(csr *x509.CertificateRequest) (err error) {
	if r.sk == nil {
		err = fmt.Errorf("private key is missing from scheme")
		return
	}
	if _, ok := (r.sk).(*rsa.PrivateKey); !ok {
		err = fmt.Errorf("issue with private key format")
		return
	}

	csrbytes, err := x509.CreateCertificateRequest(rand.Reader, csr, (r.sk).(*rsa.PrivateKey))
	if err != nil {
		err = fmt.Errorf("issue creating csr %w", err)
		return
	}
	out, err := os.OpenFile(fmt.Sprintf("%s.crt", csr.DNSNames[0]), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return
	}

	pem.Encode(out, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrbytes})
	return
}

func (r RSAScheme) MarshalPrivateKeyToPem(dns string) (err error) {
	if r.sk == nil {
		err = fmt.Errorf("private key is missing from scheme")
		return
	}

	if _, ok := (r.sk).(*rsa.PrivateKey); !ok {
		err = fmt.Errorf("issue with private key format")
		return
	}

	keyOut, err := os.OpenFile(dns+".key", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return
	}
	skBytes, err := x509.MarshalPKCS8PrivateKey(r.sk.(*rsa.PrivateKey))
	if err != nil {
		return
	}
	pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: skBytes})
	return keyOut.Close()
}
