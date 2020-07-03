package certool

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/journeyai/certool/scheme"
)

func NewScheme(s string) (sch scheme.Scheme, err error) {
	switch s {
	case "ed25519":
		sch = scheme.NewEd25519Scheme(256)
	case "rsa", "rsa2048":
		sch = scheme.NewRSAScheme(2048)
	case "rsa4096":
		sch = scheme.NewRSAScheme(4096)
	default:
		err = fmt.Errorf("unknown scheme %s", sch)
	}
	return
}
func HumanReadable(cert *x509.Certificate) string {
	return fmt.Sprintf("DNSNames: %v\nSubject: %+v\n\tIssuer: %s\nPublic Key Algorithm: %s\n\tSignature %x",
		cert.DNSNames,
		cert.Subject,
		cert.Issuer,
		cert.PublicKeyAlgorithm.String(),
		cert.Signature,
	)

}

func Verify(chain []*x509.Certificate, cert *x509.Certificate, dns string) (err error) {
	roots := x509.NewCertPool()
	for _, c := range chain {
		roots.AddCert(c)
	}
	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: x509.NewCertPool(),
		DNSName:       dns,
	}

	if _, err = cert.Verify(opts); err != nil {
		err = fmt.Errorf("invalid cert %w", err)
	}
	return
}

func VerifySystemRoots(cert *x509.Certificate, dns string) (err error) {
	opts := x509.VerifyOptions{
		DNSName: dns,
	}

	if _, err = cert.Verify(opts); err != nil {
		err = fmt.Errorf("invalid cert %w", err)
	}
	return
}

/* func Verify(root []byte, cert *x509.Certificate, dns string) (err error) {
	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM(root)
	if !ok {
		err = fmt.Errorf("asdfasdfsdf")
		return
	}
	opts := x509.VerifyOptions{
		Roots: roots,
		// Intermediates: x509.NewCertPool(),
		DNSName: dns,
	}

	if _, err = cert.Verify(opts); err != nil {
		err = fmt.Errorf("invalid cert %w", err)
	}
	return
} */
func LoadCertificate(file string) (cert *x509.Certificate, err error) {
	certbytes, err := openPEM(file)
	if err != nil {
		return
	}
	cert, err = x509.ParseCertificate(certbytes)
	return
}

func MarshalPrivateKeyToPem(sk crypto.PrivateKey, name string) (err error) {
	if sk == nil || name == "" {
		return fmt.Errorf("Secret Key or name not set")
	}

	keyOut, err := os.OpenFile(name+".key", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return
	}
	skBytes, err := x509.MarshalPKCS8PrivateKey(sk)
	if err != nil {
		return
	}
	pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: skBytes})
	return keyOut.Close()
}

func MarshalCSRToPem(csrbytes []byte) (err error) {
	csr, err := x509.ParseCertificateRequest(csrbytes)
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

func MarshalCertificateToPem(cert *x509.Certificate) (err error) {
	out, err := os.OpenFile(cert.DNSNames[0]+".crt", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return
	}
	pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	return
}
func openPEM(name string) ([]byte, error) {
	certPEM, err := ioutil.ReadFile(name)

	if err != nil {
		log.Fatal("the err is: " + err.Error())
		return nil, err
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, errors.New("Failed to parse certificate PEM " + name)
	}
	return block.Bytes, nil
}
