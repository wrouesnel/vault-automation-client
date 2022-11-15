package certutils

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
)

type ReadCertificateError struct {
	msg string
}

func (r ReadCertificateError) Error() string {
	return fmt.Sprintf("ReadCertificateError: %s", r.msg)
}

// ReadCertificate reads a certificate from the given input string dynamically,
// in the order of file path, certificate literal, base64-encoded certificate.
func ReadCertificate(input string) ([]*x509.Certificate, error) {
	certs := []*x509.Certificate{}

	var certData []byte
	if _, err := os.Stat(input); err == nil {
		certData, err = ioutil.ReadFile(input)
	} else if _, err := LoadCertificatesFromPem([]byte(input)); err == nil {
		certData = []byte(input)
	} else if certData, err = base64.StdEncoding.DecodeString(input); err == nil {
	} else {
		return certs, &ReadCertificateError{msg: "no PEM data found as filepath, literal or base64-encoded literal"}
	}

	certs, err := LoadCertificatesFromPem(certData)
	if err != nil {
		return certs, &ReadCertificateError{}
	}

	return certs, nil
}
