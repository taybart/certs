package certool

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"time"
)

// CA Certificate Authority
type CA struct {
	Cert *x509.Certificate
	sk   crypto.PrivateKey
}

// BootstrapNetwork start a new Certificate authority
func GenerateCA(scheme string) (ca CA, err error) {
	s, err := NewScheme(scheme)
	sk, pk, err := s.GenerateKeys()

	out, err := os.Create(config.CAKey)
	if err != nil {
		return
	}
	keyBytes, err := x509.MarshalPKCS8PrivateKey(sk)
	if err != nil {
		return
	}
	pem.Encode(out, &pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
	out.Close()

	csr, err := s.GenerateCSR(config.CAName)

	cert := &x509.Certificate{
		SignatureAlgorithm: csr.SignatureAlgorithm,
		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
		PublicKey:          csr.PublicKey,

		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:    config.CAName,
			Organization:  []string{"Journey"},
			Country:       []string{"US"},
			Province:      []string{"Colorado"},
			Locality:      []string{"Denver"},
			StreetAddress: []string{"1999 Broadway St"},
			PostalCode:    []string{"80202"},
		},
		DNSNames:              []string{config.CAName},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certbytes, err := x509.CreateCertificate(rand.Reader, cert, cert, pk, sk)
	if err != nil {
		return
	}

	out, err = os.Create(config.CACrt)
	if err != nil {
		return
	}
	pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: certbytes})
	out.Close()

	cert, err = x509.ParseCertificate(certbytes)

	ca = CA{Cert: cert, sk: sk}
	return
}

// LoadCA
func LoadCA() (ca CA, err error) {
	key, err := openPEM(config.CAKey)
	if err != nil {
		return
	}
	sk, err := x509.ParsePKCS8PrivateKey(key)
	if err != nil {
		return
	}

	certbytes, err := openPEM(config.CACrt)
	if err != nil {
		return
	}

	cert, err := x509.ParseCertificate(certbytes)
	if err != nil {
		return
	}

	ca = CA{Cert: cert, sk: sk}
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
		Signature:          csr.Signature,
		SignatureAlgorithm: csr.SignatureAlgorithm,

		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
		PublicKey:          csr.PublicKey,

		SerialNumber: serialNumber,
		Issuer:       ca.Cert.Subject,
		Subject:      csr.Subject,
		DNSNames:     csr.DNSNames,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour * 24 * 365),

		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageOCSPSigning},
	}
	cert, err = x509.CreateCertificate(rand.Reader, template, ca.Cert, template.PublicKey, ca.sk)
	return
}
