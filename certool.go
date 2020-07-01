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
)

func MarshalSKToPem(sk crypto.PrivateKey, dns string) (err error) {
	if sk == nil || dns == "" {
		return fmt.Errorf("Secret Key or DNS not set")
	}

	keyOut, err := os.OpenFile(dns+".key", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
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
