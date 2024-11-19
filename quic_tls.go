package scionpila

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/netsys-lab/scion-pila/pkg/logger"
)

// createTLSCertificate creates a tls.Certificate from a certificate chain and a private key
func CreateTLSCertificate(certChain []*x509.Certificate, privateKey *ecdsa.PrivateKey) ([]tls.Certificate, error) {
	// Concatenate all certificates in the chain in PEM format
	var certPEM []byte
	for _, cert := range certChain {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
	}

	// Convert the private key to PEM format
	keyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	// Create a tls.Certificate using tls.X509KeyPair
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	return []tls.Certificate{tlsCert}, nil
}

func VerifyQUICCertificateChainsHandler(trcFolder, remoteSCIONAddress string) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {

	verifier := NewSCIONPilaCertificateVerifier(trcFolder)

	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		logger.Log.Debug("Verifying certificate chain")

		var certs []*x509.Certificate

		// Parse each raw certificate in rawCerts to an *x509.Certificate
		for _, rawCert := range rawCerts {
			cert, err := x509.ParseCertificate(rawCert)
			if err != nil {
				return fmt.Errorf("failed to parse certificate: %w", err)
			}
			certs = append(certs, cert)
		}

		err := verifier.VerifyCertificateChain(certs, remoteSCIONAddress)
		if err != nil {
			return fmt.Errorf("failed to verify certificate chain: %w", err)
		}
		logger.Log.Debug("Certificate chain verified successfully")
		return nil
	}
}
