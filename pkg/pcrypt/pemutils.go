package pcrypt

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
)

// parsePEMCerts parses all certificates from a PEM chain
func ParsePEMCerts(pemChain string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for {
		block, rest := pem.Decode([]byte(pemChain))
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, errors.New("unexpected block type, expected CERTIFICATE")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
		pemChain = string(rest)
	}
	return certs, nil
}

func WriteCertsToPem(certs []*x509.Certificate) []byte {
	var pemData []byte
	for _, cert := range certs {
		pemData = append(pemData, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
	}
	return pemData
}
