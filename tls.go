package certs

import (
	"crypto/tls"
	"crypto/x509"
)

func GetPeerServerCertificateChain(uri string) (pscc []*x509.Certificate, err error) {
	// Skip verification because we just want to get the certs to print
	conn, err := tls.Dial("tcp", uri, &tls.Config{InsecureSkipVerify: true}) // #nosec
	if err != nil {
		return
	}
	defer conn.Close()
	pscc = conn.ConnectionState().PeerCertificates
	return
}
