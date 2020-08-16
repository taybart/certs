package scheme

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
)

// These types are necessary when using json encoded csr requests

type Subject struct {
	SerialNumber       string   `json:"serial_number,omitempty"`
	CommonName         string   `json:"common_name,omitempty"`
	OrganizationalUnit []string `json:"organizational_unit,omitempty"`
	Organization       []string `json:"organization,omitempty"`
	StreetAddress      []string `json:"street_address,omitempty"`
	PostalCode         []string `json:"postal_code,omitempty"`
	Locality           []string `json:"locality,omitempty"`
	Province           []string `json:"province,omitempty"`
	Country            []string `json:"country,omitempty"`
}

type CSR struct {
	Subject  Subject  `json:"subject,omitempty"`
	DNSNames []string `json:"dns_names,omitempty"`
	Scheme   string   `json:"scheme,omitempty"`
}

func CSRFromFile(filename string) (skPem pem.Block, csr *x509.CertificateRequest, err error) {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return
	}

	var c CSR
	err = json.Unmarshal(b, &c)
	if err != nil {
		return
	}

	csr = &x509.CertificateRequest{
		DNSNames: c.DNSNames,
		Subject: pkix.Name{
			SerialNumber:       c.Subject.SerialNumber,
			CommonName:         c.Subject.CommonName,
			OrganizationalUnit: c.Subject.OrganizationalUnit,
			Organization:       c.Subject.Organization,
			StreetAddress:      c.Subject.StreetAddress,
			PostalCode:         c.Subject.PostalCode,
			Locality:           c.Subject.Locality,
			Province:           c.Subject.Province,
			Country:            c.Subject.Country,
		},
	}
	s, err := NewScheme(c.Scheme)
	if err != nil {
		return
	}
	skPem, err = s.AddCryptoToCSR(csr)
	if err != nil {
		return
	}
	return
}
