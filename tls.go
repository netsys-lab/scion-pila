package scionpila

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
)

// createTLSCertificate creates a tls.Certificate from an *x509.Certificate and a private key
func CreateTLSCertificate(cert *x509.Certificate, privateKey *ecdsa.PrivateKey) (tls.Certificate, error) {
	// Convert the certificate to PEM format
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

	// Convert the private key to PEM format
	keyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	// Create a tls.Certificate using tls.X509KeyPair
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tlsCert, nil
}
