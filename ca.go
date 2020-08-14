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
	if err != nil {
		return
	}
	sk, pk, err := s.GenerateKeys()
	if err != nil {
		return
	}

	out, err := os.Create(config.CAKey)
	if err != nil {
		return
	}
	keyBytes, err := x509.MarshalPKCS8PrivateKey(sk)
	if err != nil {
		return
	}
	if config.GetCAPassword() != "_" {
		var block *pem.Block
		block, err = x509.EncryptPEMBlock(rand.Reader, "PRIVATE KEY", keyBytes, []byte(config.GetCAPassword()), x509.PEMCipherAES256)
		if err != nil {
			return
		}
		err = pem.Encode(out, block)
		if err != nil {
			return
		}
	} else {
		err = pem.Encode(out, &pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
		if err != nil {
			return
		}
	}
	err = out.Close()
	if err != nil {
		return
	}

	csr, err := s.GenerateCSR(config.CAName)
	if err != nil {
		return
	}

	cert := &x509.Certificate{
		SignatureAlgorithm: csr.SignatureAlgorithm,
		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
		PublicKey:          csr.PublicKey,

		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:         config.CAName,
			Organization:       []string{"Journey"},
			OrganizationalUnit: []string{"Engineering"},
			Country:            []string{"US"},
			Province:           []string{"Colorado"},
			Locality:           []string{"Denver"},
			StreetAddress:      []string{"1999 Broadway St"},
			PostalCode:         []string{"80202"},
		},
		DNSNames:  []string{config.CAName},
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

	out, err = os.Create(config.CACrt)
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

	ca = CA{Cert: cert, sk: sk}
	return
}

// LoadCA
func LoadCA() (ca CA, err error) {
	key, err := openPEM(config.CAKey)
	if err != nil {
		return
	}
	keybytes := key.Bytes
	if x509.IsEncryptedPEMBlock(key) {
		keybytes, err = x509.DecryptPEMBlock(key, []byte(config.GetCAPassword()))
		if err != nil {
			return
		}
	}
	sk, err := x509.ParsePKCS8PrivateKey(keybytes)
	if err != nil {
		return
	}

	certblock, err := openPEM(config.CACrt)
	if err != nil {
		return
	}

	cert, err := x509.ParseCertificate(certblock.Bytes)
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
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	cert, err = x509.CreateCertificate(rand.Reader, template, ca.Cert, template.PublicKey, ca.sk)
	return
}

// SignCARequest signs x509 certificate request
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
		NotAfter:  time.Now().AddDate(10, 0, 0),

		IsCA:                  true,
		BasicConstraintsValid: true,

		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageOCSPSigning},
	}

	cert, err = x509.CreateCertificate(rand.Reader, template, ca.Cert, template.PublicKey, ca.sk)
	return
}
