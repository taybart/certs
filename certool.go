package certool

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"html/template"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
	"time"
)

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
	certs, err := LoadCertificates(config.CA.Crt)
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

	templ := `DNSNames: {{ .C.DNSNames }}
Valid: {{ .C.NotBefore | formattime }} - {{ .C.NotAfter | formattime }}
SerialNumber: {{ .C.SerialNumber }}
{{ if .C.IsCA }}
Certificate is a CA
{{ end }}
Subject: {{ .C.Subject.CommonName }}
	 {{ if notempty .C.Subject.Organization }}{{ index .C.Subject.Organization 0 }}{{end}} {{ if notempty .C.Subject.OrganizationalUnit }}{{ index .C.Subject.OrganizationalUnit 0 }}{{ end }}
	 {{ if notempty .C.Subject.StreetAddress }}{{ index .C.Subject.StreetAddress 0 }} {{end}}{{ if notempty .C.Subject.Locality }}{{ index .C.Subject.Locality 0 }}, {{end}}{{ if notempty .C.Subject.Province }}{{ index .C.Subject.Province 0 }}{{end}}{{ if notempty .C.Issuer.Country }}, {{ index .C.Issuer.Country 0 }}{{end}}

Issuer:  {{ .C.Issuer.CommonName }}
	 {{ if notempty .C.Issuer.Organization }}{{ index .C.Issuer.Organization 0 }}{{end}} {{ if notempty .C.Issuer.OrganizationalUnit }}{{ index .C.Issuer.OrganizationalUnit 0 }}{{ end }}
	 {{ if notempty .C.Issuer.StreetAddress }}{{ index .C.Issuer.StreetAddress 0 }} {{end}}{{ if notempty .C.Issuer.Locality }}{{ index .C.Issuer.Locality 0 }}, {{end}}{{ if notempty .C.Issuer.Province }}{{ index .C.Issuer.Province 0 }}{{end}}{{ if notempty .C.Issuer.Country }}, {{ index .C.Issuer.Country 0 }}{{end}}

KeyUsage: {{ .KeyUsages }}
ExtKeyUsage: {{ .ExtKeyUsages }}

PublicKeyAlgorithm: {{ .C.PublicKeyAlgorithm }}

SignatureAlgorithm: {{ .C.SignatureAlgorithm }}
Signature:
{{ .C.Signature | printf "%x" | wrapsig 50 | indent 6 }}
{{- if .C.OCSPServer }}
OCSPServer: {{ .C.OCSPServer }}
{{- end -}}
`
	funcMap := template.FuncMap{
		"notempty": func(arr []string) bool {
			if len(arr) == 1 {
				return arr[0] != ""
			}
			return len(arr) != 0
		},
		"indent": func(spaces int, v string) string {
			pad := strings.Repeat(" ", spaces)
			return pad + strings.Replace(v, "\n", "\n"+pad, -1)
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
	t := template.Must(template.New("cert").Funcs(funcMap).Parse(templ))

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

func LoadCertificates(file string) (certs []*x509.Certificate, err error) {
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
	err = pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: skBytes})
	if err != nil {
		return
	}
	return keyOut.Close()
}

func WritePemToFile(name string, block *pem.Block) (err error) {
	keyOut, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return
	}
	err = pem.Encode(keyOut, block)
	if err != nil {
		return
	}
	return keyOut.Close()
}

func MarshalCSRToPem(csr *x509.CertificateRequest) (err error) {
	out, err := os.OpenFile(csr.DNSNames[0]+".csr", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return
	}
	err = pem.Encode(out, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr.Raw})
	return
}

func MarshalCertificateToPem(cert *x509.Certificate) (err error) {
	out, err := os.OpenFile(cert.DNSNames[0]+".crt", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return
	}
	err = pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	return
}

func openPEM(name string) (blocks []*pem.Block, err error) {
	pembytes, err := ioutil.ReadFile(name)
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
