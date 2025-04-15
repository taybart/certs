package certs

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/taybart/certs/scheme"
	"github.com/taybart/log"
)

// CA Certificate Authority
type CA struct {
	Cert *x509.Certificate
	sk   crypto.PrivateKey
	sch  scheme.Scheme
}

// GenerateCA start a new Certificate authority
func GenerateCA(sch scheme.Scheme, profile string) (*CA, error) {
	sk, pk, err := sch.GenerateKeys()
	if err != nil {
		return nil, err
	}

	directory := fmt.Sprintf("%s/profiles/%s", config.Dir, profile)
	if err := os.MkdirAll(directory, os.ModePerm); err != nil {
		return nil, err
	}
	b, err := json.MarshalIndent(config, "", "\t")
	if err != nil {
		return nil, err
	}
	os.WriteFile(fmt.Sprintf("%s/config.json", directory), b, os.ModePerm)

	out, err := os.Create(config.CA.Key)
	if err != nil {
		return nil, err
	}
	skPem, err := sch.PrivateKeyToPem()
	if err != nil {
		return nil, err
	}
	err = pem.Encode(out, skPem)
	if err != nil {
		return nil, err
	}
	err = out.Close()
	if err != nil {
		return nil, err
	}

	_, csr, err := sch.GenerateDefaultCSR(config.CA.Name)
	if err != nil {
		return nil, err
	}

	sub := config.DefaultSubject.ToPKIXName()
	sub.CommonName = config.CA.Name
	cert := &x509.Certificate{
		SignatureAlgorithm: csr.SignatureAlgorithm,
		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
		PublicKey:          csr.PublicKey,

		SerialNumber: big.NewInt(1),
		Subject:      sub,
		DNSNames:     []string{config.CA.Name},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),

		IsCA:                  true,
		BasicConstraintsValid: true,

		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}

	certbytes, err := x509.CreateCertificate(rand.Reader, cert, cert, pk, sk)
	if err != nil {
		return nil, err
	}

	out, err = os.Create(config.CA.Crt)
	if err != nil {
		return nil, err
	}
	err = pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: certbytes})
	if err != nil {
		return nil, err
	}
	err = out.Close()
	if err != nil {
		return nil, err
	}

	cert, err = x509.ParseCertificate(certbytes)
	if err != nil {
		return nil, err
	}

	return &CA{Cert: cert, sk: sk, sch: sch}, nil
}

// LoadCA
func LoadCA() (ca CA, err error) {
	keys, err := openPEM(config.CA.Key)
	if err != nil {
		err = fmt.Errorf("could not load ca key file %w", err)
		return
	}
	keybytes := keys[0].Bytes
	// TODO: use AES instead
	if x509.IsEncryptedPEMBlock(keys[0]) {
		keybytes, err = x509.DecryptPEMBlock(keys[0], config.GetCAPassword())
		if err != nil {
			fmt.Println(log.Red, "✗", log.Rtd)
			return
		}
		fmt.Println(log.Green, "✓", log.Rtd)
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
func (ca *CA) SignRequest(asn1Data []byte) (*x509.Certificate, error) {
	csr, err := x509.ParseCertificateRequest(asn1Data)
	if err != nil {
		return nil, err
	}

	if err = csr.CheckSignature(); err != nil {
		return nil, err
	}

	// Create template for certificate creation, uses properties from the request and root certificate.
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
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
	certBytes, err := x509.CreateCertificate(rand.Reader, template, ca.Cert, template.PublicKey, ca.sk)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(certBytes)
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
