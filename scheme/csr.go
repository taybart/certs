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
	CommonName         string   `json:"common_name,omitempty" label:"Common Name"`
	OrganizationalUnit []string `json:"organizational_unit,omitempty" label:"Organizational Unit"`
	Organization       []string `json:"organization,omitempty" label:"Organization"`
	StreetAddress      []string `json:"street_address,omitempty" label:"Street Address"`
	PostalCode         []string `json:"postal_code,omitempty" label:"Postal Code"`
	Locality           []string `json:"locality,omitempty" label:"Locality [ex. Denver]"`
	Province           []string `json:"province,omitempty" label:"Province [ex. Colorado]"`
	Country            []string `json:"country,omitempty" label:"Country [ex. US]"`
}

type CSR struct {
	Subject  Subject  `json:"subject,omitempty"`
	DNSNames []string `json:"dns_names,omitempty"`
	Scheme   string   `json:"scheme,omitempty"`
}

func (s Subject) ToPKIXName() pkix.Name {
	return pkix.Name{
		SerialNumber:       s.SerialNumber,
		CommonName:         s.CommonName,
		OrganizationalUnit: s.OrganizationalUnit,
		Organization:       s.Organization,
		StreetAddress:      s.StreetAddress,
		PostalCode:         s.PostalCode,
		Locality:           s.Locality,
		Province:           s.Province,
		Country:            s.Country,
	}
}
func CSRFromFile(filename string) (skPem *pem.Block, csr *x509.CertificateRequest, err error) {
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
