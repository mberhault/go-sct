package sct

import (
	"crypto/x509"
	"fmt"

	ctx509 "github.com/google/certificate-transparency-go/x509"
)

func buildCertificateChain(certs []*x509.Certificate) ([]*ctx509.Certificate, error) {
	chain := make([]*ctx509.Certificate, len(certs))

	for i, cert := range certs {
		newCert, err := ctx509.ParseCertificate(cert.Raw)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %v", err)
		}

		chain[i] = newCert
	}

	return chain, nil
}
