package certs

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"fmt"
	"html/template"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

//go:embed certificate.tmpl
var certificateTemplate string

func CAExists() bool {
	_, err := os.Stat(config.CA.Key)
	return err == nil
}

func EditConfig() error {
	cmd := exec.Command(os.Getenv("EDITOR"), fmt.Sprintf("%s/config.json", config.Dir))
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		return err
	}
	return nil
}

func GetCACert() (*x509.Certificate, error) {
	certs, err := LoadCertsFromFile(config.CA.Crt)
	if err != nil {
		return nil, err
	}
	return certs[0], nil
}

func HumanReadable(cert *x509.Certificate) string {
	keyusages := getKeyUsage(cert)
	extkeyusages := getExtKeyUsage(cert)
	values := struct {
		C            *x509.Certificate
		KeyUsages    []string
		ExtKeyUsages []string
	}{
		C:            cert,
		KeyUsages:    keyusages,
		ExtKeyUsages: extkeyusages,
	}

	funcMap := template.FuncMap{
		"notempty": func(arr []string) bool {
			if len(arr) == 1 {
				return arr[0] != ""
			}
			return len(arr) != 0
		},
		"indent": func(spaces int, v string) string {
			pad := strings.Repeat(" ", spaces)
			v = strings.ReplaceAll(v, "\n", "\n"+pad)
			return fmt.Sprintf("%s%s", pad, v)
		},
		"wrapsig": func(width int, str string) (wrapped string) {
			for i, c := range str {
				if i%width == 0 && i != 0 {
					wrapped += "\n"
				}
				wrapped += string(c)
			}
			return
		},
		"formattime": func(date time.Time) string {
			return date.Format("Jan 2, 2006")
		},
	}
	t := template.Must(template.New("cert").Funcs(funcMap).Parse(certificateTemplate))

	var out bytes.Buffer
	err := t.Execute(&out, values)
	if err != nil {
		fmt.Println(err)
	}
	return out.String()
}

func getKeyUsage(cert *x509.Certificate) (keyusages []string) {
	keyUsageToString := map[x509.KeyUsage]string{
		x509.KeyUsageDigitalSignature:  "DigitalSignature",
		x509.KeyUsageContentCommitment: "ContentCommitment",
		x509.KeyUsageKeyEncipherment:   "KeyEncipherment",
		x509.KeyUsageDataEncipherment:  "DataEncipherment",
		x509.KeyUsageKeyAgreement:      "KeyAgreement",
		x509.KeyUsageCertSign:          "CertSign",
		x509.KeyUsageCRLSign:           "CRLSign",
		x509.KeyUsageEncipherOnly:      "EncipherOnly",
		x509.KeyUsageDecipherOnly:      "DecipherOnly",
	}
	for k, v := range keyUsageToString {
		if k&cert.KeyUsage != 0 {
			keyusages = append(keyusages, v)
		}
	}
	return
}

func getExtKeyUsage(cert *x509.Certificate) (extkeyusages []string) {
	extKeyUsageToString := map[x509.ExtKeyUsage]string{
		x509.ExtKeyUsageAny:                            "Any",
		x509.ExtKeyUsageServerAuth:                     "ServerAuth",
		x509.ExtKeyUsageClientAuth:                     "ClientAuth",
		x509.ExtKeyUsageCodeSigning:                    "CodeSigning",
		x509.ExtKeyUsageEmailProtection:                "EmailProtection",
		x509.ExtKeyUsageIPSECEndSystem:                 "IPSECEndSystem",
		x509.ExtKeyUsageIPSECTunnel:                    "IPSECTunnel",
		x509.ExtKeyUsageIPSECUser:                      "IPSECUser",
		x509.ExtKeyUsageTimeStamping:                   "TimeStamping",
		x509.ExtKeyUsageOCSPSigning:                    "OCSPSigning",
		x509.ExtKeyUsageMicrosoftServerGatedCrypto:     "MicrosoftServerGatedCrypto",
		x509.ExtKeyUsageNetscapeServerGatedCrypto:      "NetscapeServerGatedCrypto",
		x509.ExtKeyUsageMicrosoftCommercialCodeSigning: "MicrosoftCommercialCodeSigning",
		x509.ExtKeyUsageMicrosoftKernelCodeSigning:     "MicrosoftKernelCodeSigning",
	}
	for _, v := range cert.ExtKeyUsage {
		extkeyusages = append(extkeyusages, extKeyUsageToString[v])
	}
	return
}

// asdf
func Verify(cert *x509.Certificate, chain []*x509.Certificate, dns string) (err error) {
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

// asdf
func VerifySystemRoots(cert *x509.Certificate, intermediateChain []*x509.Certificate, dns string) (err error) {
	intermediates := x509.NewCertPool()
	for _, c := range intermediateChain {
		intermediates.AddCert(c)
	}
	_, err = cert.Verify(x509.VerifyOptions{
		DNSName:       dns,
		Intermediates: intermediates,
	})
	if err != nil {
		err = fmt.Errorf("invalid cert %w", err)
	}
	return
}

func LoadCertsFromFile(file string) (certs []*x509.Certificate, err error) {
	certblocks, err := openPEM(file)
	if err != nil {
		return
	}
	for _, certblock := range certblocks {
		var cert *x509.Certificate
		cert, err = x509.ParseCertificate(certblock.Bytes)
		if err != nil {
			return
		}
		certs = append(certs, cert)
	}
	return
}

// asdf
func MarshalPrivateKeyToPem(sk crypto.PrivateKey, name string) (err error) {
	if sk == nil || name == "" {
		return fmt.Errorf("secret key or name not set")
	}

	keyOut, err := os.OpenFile(fmt.Sprintf("%s.key", name),
		os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return
	}
	skBytes, err := x509.MarshalPKCS8PrivateKey(sk)
	if err != nil {
		return
	}
	err = pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: skBytes})
	if err != nil {
		return
	}
	return keyOut.Close()
}

func WritePemToFile(name string, block *pem.Block) error {
	keyOut, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	err = pem.Encode(keyOut, block)
	if err != nil {
		return err
	}
	return keyOut.Close()
}

func WriteCSR(csr *x509.CertificateRequest) (err error) {
	out, err := os.OpenFile(fmt.Sprintf("%s.csr", csr.DNSNames[0]),
		os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return
	}
	return pem.Encode(out, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr.Raw})
}

func WriteCertificate(cert *x509.Certificate) (err error) {
	out, err := os.OpenFile(fmt.Sprintf("%s.crt", cert.DNSNames[0]),
		os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return
	}
	return pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

func Decrypt(password, ciphertext []byte) ([]byte, error) {
	gcm, err := newGCM(password)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func Encrypt(password, plaintext []byte) ([]byte, error) {
	gcm, err := newGCM(password)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func newGCM(password []byte) (cipher.AEAD, error) {
	hash := sha256.Sum256([]byte(password))

	c, err := aes.NewCipher(hash[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(c)
}

func openPEM(name string) (blocks []*pem.Block, err error) {
	pembytes, err := os.ReadFile(name)
	if err != nil {
		return
	}
	block, rest := pem.Decode(pembytes)
	blocks = append(blocks, block)
	if rest != nil {
		var lastloop []byte
		for {
			block, rest = pem.Decode(rest)
			if rest == nil || bytes.Equal(rest, lastloop) {
				return
			}
			lastloop = rest
			if block != nil {
				blocks = append(blocks, block)
			}
		}
	}
	return
}
