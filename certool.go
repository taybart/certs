package certool

import (
	"bufio"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
)

type Config struct {
	Dir        string `json:"dir"`
	CAName     string `json:"caName"`
	CAKey      string `json:"caKey"`
	CACrt      string `json:"caCrt"`
	CAPassword string `json:"caPassword"`
}

var DefaultConfig = Config{
	Dir:        fmt.Sprintf("%s/.config/certool", os.Getenv("HOME")),
	CAName:     "ca.journey",
	CAKey:      fmt.Sprintf("%s/.config/certool/%s.key", os.Getenv("HOME"), "ca.journey"),
	CACrt:      fmt.Sprintf("%s/.config/certool/%s.crt", os.Getenv("HOME"), "ca.journey"),
	CAPassword: "123456",
}

var config = DefaultConfig

func LoadConfig() (err error) {
	if _, err = os.Stat(config.Dir); os.IsNotExist(err) {
		err = os.MkdirAll(config.Dir, 0755)
		if err != nil {
			err = fmt.Errorf("issue creating config folder %w", err)
			return
		}
	}
	if _, err = os.Stat(fmt.Sprintf("%s/config.json", config.Dir)); os.IsNotExist(err) {
		var file []byte
		file, err = json.MarshalIndent(config, "", " ")
		if err != nil {
			err = fmt.Errorf("issue marshalling config file %w", err)
			return
		}

		err = ioutil.WriteFile(fmt.Sprintf("%s/config.json", config.Dir), file, 0644)
		if err != nil {
			err = fmt.Errorf("issue writing config file %w", err)
			return
		}
		fmt.Println("[WARNING] default password used")
		return
	}

	c, err := ioutil.ReadFile(fmt.Sprintf("%s/config.json", config.Dir))
	if err != nil {
		err = fmt.Errorf("issue reading config %w", err)
		return
	}
	json.Unmarshal(c, &config)
	if config.CAPassword == "" {
		fmt.Print("Enter CA password: ")
		reader := bufio.NewReader(os.Stdin)
		config.CAPassword, err = reader.ReadString('\n')
		if err != nil {
			return
		}
	}
	if config.CAPassword == DefaultConfig.CAPassword {
		fmt.Println("[WARNING] default password used")
	}
	if config.CAPassword == "_" {
		config.CAPassword = ""
	}
	return
}
func LoadConfigFromFile(location string) (err error) {
	c, err := ioutil.ReadFile(fmt.Sprintf("%s/config.json", location))
	if err != nil {
		err = fmt.Errorf("issue reading config %w", err)
		return
	}
	json.Unmarshal(c, &config)
	if config.CAPassword == DefaultConfig.CAPassword {
		fmt.Println("WARNING")
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

func MarshalSKToPem(sk crypto.PrivateKey, name string) (err error) {
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
