package certool

import (
	"crypto/tls"
	"crypto/x509"
)

func GetPeerServerCertificateChain(dns string) (pscc []*x509.Certificate, err error) {
	conn, err := tls.Dial("tcp", dns, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return
	}
	defer conn.Close()
	pscc = conn.ConnectionState().PeerCertificates
	return
}
