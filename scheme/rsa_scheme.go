package scheme

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
	r.pk = &rsask.PublicKey
	return rsask, &rsask.PublicKey, nil
}

func (r *RSAScheme) AddCryptoToCSR(csr *x509.CertificateRequest) (skPem pem.Block, err error) {
	if r.sk == nil {
		_, _, err = r.GenerateKeys()
		if err != nil {
			err = fmt.Errorf("issue generating keys for scheme %s %w", r.String(), err)
			return
		}
	}

	csr.SignatureAlgorithm = x509.SHA256WithRSA
	csr.PublicKeyAlgorithm = x509.RSA
	csr.PublicKey = r.pk

	csrbytes, err := x509.CreateCertificateRequest(rand.Reader, csr, r.sk)
	if err != nil {
		err = fmt.Errorf("issue creating csr %w", err)
		return
	}

	newcsr, err := x509.ParseCertificateRequest(csrbytes)
	if err != nil {
		return
	}
	*csr = *newcsr

	skPem, err = r.PrivateKeyToPem()
	if err != nil {
		return
	}
	return
}

func (r *RSAScheme) GenerateDefaultCSR(dns string) (skPem pem.Block, csr *x509.CertificateRequest, err error) {
	sk, pk, err := r.GenerateKeys()
	if err != nil {
		err = fmt.Errorf("issue generating keys for scheme %s %w", r.String(), err)
		return
	}
	csr = &x509.CertificateRequest{
		SignatureAlgorithm: x509.SHA256WithRSA,
		PublicKeyAlgorithm: x509.RSA,
		PublicKey:          pk,
		Subject: pkix.Name{
			CommonName:         dns,
			Organization:       []string{"Journey"},
			OrganizationalUnit: []string{"Engineering"},
			Country:            []string{"US"},
			Province:           []string{"Colorado"},
			Locality:           []string{"Denver"},
			StreetAddress:      []string{"1999 Broadway St"},
			PostalCode:         []string{"80202"},
		},
		DNSNames: []string{dns},
	}
	csrbytes, err := x509.CreateCertificateRequest(rand.Reader, csr, sk)
	if err != nil {
		err = fmt.Errorf("issue creating csr %w", err)
		return
	}
	csr, err = x509.ParseCertificateRequest(csrbytes)
	if err != nil {
		err = fmt.Errorf("issue parsing csr %w", err)
		return
	}

	skPem, err = r.PrivateKeyToPem()
	if err != nil {
		return
	}
	return
}

func (r RSAScheme) PrivateKeyToPem() (skPem pem.Block, err error) {
	if r.sk == nil {
		err = fmt.Errorf("private key is missing from scheme")
		return
	}

	if _, ok := (r.sk).(*rsa.PrivateKey); !ok {
		err = fmt.Errorf("issue with private key format")
		return
	}

	skBytes := x509.MarshalPKCS1PrivateKey(r.sk.(*rsa.PrivateKey))
	if err != nil {
		return
	}
	skPem = pem.Block{Type: "RSA PRIVATE KEY", Bytes: skBytes}
	return
}

func (r RSAScheme) MarshalPrivateKeyToFile(dns string) (err error) {
	skPem, err := r.PrivateKeyToPem()
	if err != nil {
		return
	}
	keyOut, err := os.OpenFile(dns+".key", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return
	}
	err = pem.Encode(keyOut, &skPem)
	if err != nil {
		return
	}
	return keyOut.Close()
}
