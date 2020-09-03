package scheme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"
)

type ECDSAScheme struct {
	sk   *ecdsa.PrivateKey
	pk   *ecdsa.PublicKey
	size int
}

func (r ECDSAScheme) String() string {
	return "ecdsa"
}
func NewECDSAScheme(size int) *ECDSAScheme {
	return &ECDSAScheme{
		size: size,
	}
}

func NewECDSASchemeFromKeys(sk *ecdsa.PrivateKey, pk *ecdsa.PublicKey) *ECDSAScheme {
	return &ECDSAScheme{
		size: sk.D.BitLen(),
		sk:   sk,
		pk:   pk,
	}
}

func (e *ECDSAScheme) GenerateKeys() (sk crypto.PrivateKey, pk crypto.PublicKey, err error) {
	switch e.size {
	case 256:
		e.sk, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case 384:
		e.sk, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case 521:
		e.sk, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	default:
		panic("Unknown curve for ecdsa")
	}
	if err != nil {
		panic(err)
	}
	e.pk = &e.sk.PublicKey
	return e.sk, e.pk, nil
}

func (e *ECDSAScheme) GetSignatureAlgorithm() x509.SignatureAlgorithm {
	return x509.ECDSAWithSHA256
}

func (e *ECDSAScheme) AddCryptoToCSR(csr *x509.CertificateRequest) (skPem *pem.Block, err error) {
	if e.sk == nil {
		_, _, err = e.GenerateKeys()
		if err != nil {
			err = fmt.Errorf("issue generating keys for scheme %s %w", e.String(), err)
			return
		}
	}

	csr.SignatureAlgorithm = x509.ECDSAWithSHA256
	csr.PublicKeyAlgorithm = x509.ECDSA
	csr.PublicKey = e.pk

	csrbytes, err := x509.CreateCertificateRequest(rand.Reader, csr, e.sk)
	if err != nil {
		err = fmt.Errorf("issue creating csr %w", err)
		return
	}

	newcsr, err := x509.ParseCertificateRequest(csrbytes)
	if err != nil {
		return
	}
	*csr = *newcsr

	skPem, err = e.PrivateKeyToPem()
	if err != nil {
		return
	}
	return
}

func (e *ECDSAScheme) GenerateDefaultCSR(dns string) (skPem *pem.Block, csr *x509.CertificateRequest, err error) {
	if e.sk == nil {
		_, _, err = e.GenerateKeys()
		if err != nil {
			err = fmt.Errorf("issue generating keys for scheme %s %w", e.String(), err)
			return
		}
	}

	csr = &x509.CertificateRequest{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		PublicKeyAlgorithm: x509.ECDSA,
		PublicKey:          &e.pk,
		Subject: pkix.Name{
			CommonName:         dns,
			Organization:       []string{"Journey"},
			OrganizationalUnit: []string{"Engineering"},
			Country:            []string{"US"},
			Province:           []string{"Colorado"},
			Locality:           []string{"Denver"},
			StreetAddress:      []string{""},
			PostalCode:         []string{""},
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
	skPem, err = e.PrivateKeyToPem()
	if err != nil {
		return
	}
	return
}

func (e ECDSAScheme) PrivateKeyToPem() (skPem *pem.Block, err error) {
	if e.sk == nil {
		err = fmt.Errorf("private key is missing from scheme")
		return
	}

	skBytes, err := x509.MarshalPKCS8PrivateKey((e.sk))
	if err != nil {
		return
	}

	skPem = &pem.Block{Type: "EC PRIVATE KEY", Bytes: skBytes}
	pw := readPassword()
	if pw != nil {
		skPem, err = x509.EncryptPEMBlock(rand.Reader, skPem.Type, skPem.Bytes, []byte(pw), x509.PEMCipherAES256)
		if err != nil {
			return
		}
	}
	return
}
func (e ECDSAScheme) MarshalPrivateKeyToFile(dns string) (err error) {
	skPem, err := e.PrivateKeyToPem()
	if err != nil {
		return
	}
	keyOut, err := os.OpenFile(dns+".key", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return
	}
	err = pem.Encode(keyOut, skPem)
	if err != nil {
		return
	}
	return keyOut.Close()
}
