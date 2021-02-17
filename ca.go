package certs

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/taybart/certs/scheme"
)

// CA Certificate Authority
type CA struct {
	Cert *x509.Certificate
	sk   crypto.PrivateKey
	sch  scheme.Scheme
}

// BootstrapNetwork start a new Certificate authority
func GenerateCA(sch string) (ca CA, err error) {
	s, err := scheme.NewScheme(sch)
	if err != nil {
		return
	}
	sk, pk, err := s.GenerateKeys()
	if err != nil {
		return
	}

	out, err := os.Create(config.CA.Key)
	if err != nil {
		return
	}
	skPem, err := s.PrivateKeyToPem()
	err = pem.Encode(out, skPem)
	if err != nil {
		return
	}
	err = out.Close()
	if err != nil {
		return
	}

	_, csr, err := s.GenerateDefaultCSR(config.CA.Name)
	if err != nil {
		return
	}

	cert := &x509.Certificate{
		SignatureAlgorithm: csr.SignatureAlgorithm,
		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
		PublicKey:          csr.PublicKey,

		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:         config.CA.Name,
			Organization:       []string{"Company"},
			OrganizationalUnit: []string{"Engineering"},
			Country:            []string{"US"},
			Province:           []string{"Colorado"},
			Locality:           []string{"Denver"},
			StreetAddress:      []string{""},
			PostalCode:         []string{""},
		},
		DNSNames:  []string{config.CA.Name},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(10, 0, 0),

		IsCA:                  true,
		BasicConstraintsValid: true,

		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}

	certbytes, err := x509.CreateCertificate(rand.Reader, cert, cert, pk, sk)
	if err != nil {
		return
	}

	out, err = os.Create(config.CA.Crt)
	if err != nil {
		return
	}
	err = pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: certbytes})
	if err != nil {
		return
	}
	err = out.Close()
	if err != nil {
		return
	}

	cert, err = x509.ParseCertificate(certbytes)
	if err != nil {
		return
	}

	ca = CA{Cert: cert, sk: sk, sch: s}
	return
}

// LoadCA
func LoadCA() (ca CA, err error) {
	keys, err := openPEM(config.CA.Key)
	if err != nil {
		return
	}
	keybytes := keys[0].Bytes
	if x509.IsEncryptedPEMBlock(keys[0]) {
		keybytes, err = x509.DecryptPEMBlock(keys[0], config.GetCAPassword())
		if err != nil {
			fmt.Printf("\033[31m✗\033[0m\n")
			return
		}
		fmt.Printf("\033[32m✓\033[0m\n")
	}
	sk, err := x509.ParsePKCS8PrivateKey(keybytes)
	if err != nil {
		return
	}

	certblocks, err := openPEM(config.CA.Crt)
	if err != nil {
		return
	}

	cert, err := x509.ParseCertificate(certblocks[0].Bytes)
	if err != nil {
		return
	}
	sch, err := scheme.SchemeFromKey(sk, cert.PublicKey)
	if err != nil {
		return
	}

	ca = CA{Cert: cert, sk: sk, sch: sch}
	return
}

// SignRequest signs x509 certificate request
func (ca *CA) SignRequest(asn1Data []byte) (cert []byte, err error) {
	csr, err := x509.ParseCertificateRequest(asn1Data)
	if err != nil {
		return
	}

	if err = csr.CheckSignature(); err != nil {
		return
	}

	// Create template for certificate creation, uses properties from the request and root certificate.
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return
	}
	// Client Template
	template := &x509.Certificate{
		SignatureAlgorithm: ca.sch.GetSignatureAlgorithm(),

		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
		PublicKey:          csr.PublicKey,

		SerialNumber: serialNumber,
		Issuer:       ca.Cert.Subject,
		Subject:      csr.Subject,
		DNSNames:     csr.DNSNames,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour * 24 * 365),

		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	cert, err = x509.CreateCertificate(rand.Reader, template, ca.Cert, template.PublicKey, ca.sk)
	return
}

// SignCA.Request signs x509 certificate request
func (ca *CA) SignCARequest(asn1Data []byte) (cert []byte, err error) {
	csr, err := x509.ParseCertificateRequest(asn1Data)
	if err != nil {
		return
	}

	if err = csr.CheckSignature(); err != nil {
		return
	}

	// Create template for certificate creation, uses properties from the request and root certificate.
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return
	}
	// Client Template
	template := &x509.Certificate{
		Signature:          csr.Signature,
		SignatureAlgorithm: csr.SignatureAlgorithm,

		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
		PublicKey:          csr.PublicKey,

		SerialNumber: serialNumber,
		Issuer:       ca.Cert.Subject,
		Subject:      csr.Subject,
		DNSNames:     csr.DNSNames,

		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(3, 0, 0),

		IsCA:                  true,
		BasicConstraintsValid: true,

		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageOCSPSigning},
	}

	cert, err = x509.CreateCertificate(rand.Reader, template, ca.Cert, template.PublicKey, ca.sk)
	return
}
