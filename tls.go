package certs

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
)

func GetPeerServerCertChain(remote string) ([]*x509.Certificate, error) {
	u, err := url.Parse(remote)
	if err != nil {
		return nil, err
	}
	host := u.Hostname()
	port := u.Port()
	if host == "" {
		host, port, err = net.SplitHostPort(remote)
		if err != nil {
			return nil, err
		}
	}

	if port == "" {
		port = "443"
	}

	// Skip verification because we just want to get the certs to print
	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%s", host, port), &tls.Config{InsecureSkipVerify: true}) // #nosec
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return conn.ConnectionState().PeerCertificates, nil
}
