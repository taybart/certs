package certool

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"os"

	"github.com/Masterminds/sprig"
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

	templ := `DNSNames: {{ .C.DNSNames }}
SerialNumber: {{ .C.SerialNumber }}
{{ if .C.IsCA }}
Certificate is a CA
{{ end }}
Subject: {{ .C.Subject.CommonName }}
	 {{ if ne (len .C.Subject.Organization) 0 }}{{ index .C.Subject.Organization 0 }}{{end}} {{ if ne (len .C.Subject.OrganizationalUnit) 0 }}{{ index .C.Subject.OrganizationalUnit 0 }}{{ end }}
	 {{ if ne (len .C.Subject.StreetAddress) 0 }}{{ index .C.Subject.StreetAddress 0 }}, {{end}}{{ if ne (len .C.Subject.Locality) 0 }}{{ index .C.Subject.Locality 0 }}{{end}}{{ if ne (len .C.Subject.Province) 0 }} {{ index .C.Subject.Province 0 }}{{end}}

Issuer:  {{ .C.Issuer.CommonName }}
	 {{ if ne (len .C.Issuer.Organization) 0 }}{{ index .C.Issuer.Organization 0 }}{{end}} {{ if ne (len .C.Issuer.OrganizationalUnit) 0 }}{{ index .C.Issuer.OrganizationalUnit 0 }}{{ end }}
	 {{ if ne (len .C.Issuer.StreetAddress) 0 }}{{ index .C.Issuer.StreetAddress 0 }}, {{end}}{{ if ne (len .C.Issuer.Locality) 0 }}{{ index .C.Issuer.Locality 0 }}{{end}}{{ if ne (len .C.Issuer.Province) 0 }} {{ index .C.Issuer.Province 0 }}{{end}}

KeyUsage: {{ .KeyUsages }}
ExtKeyUsage: {{ .ExtKeyUsages }}

PublicKeyAlgorithm: {{ .C.PublicKeyAlgorithm }}
SignatureAlgorithm: {{ .C.SignatureAlgorithm }}

Signature:
{{ .C.Signature | printf "%x" | wrapWith 50 "\n"  | indent 6 }}
{{- if .C.OCSPServer }}
OCSPServer: {{ .C.OCSPServer }}
{{- end -}}
`

	t := template.Must(template.New("cert").Funcs(sprig.FuncMap()).Parse(templ))
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
