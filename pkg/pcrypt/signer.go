package pcrypt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"
)

type SCIONPilaSignedCertificate struct {
	CertificateChain []byte
	PrivateKey       []byte
}

type SCIONPilaSignedCertificateRequest struct {
	CertificateChain []byte
}

type SCIONPilaCertificateSigner struct {
	caKeyPath  string
	caCertPath string

	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey
}

func NewSCIONPilaCertificateSigner(caKeyPath, caCertPath string) *SCIONPilaCertificateSigner {
	caCert, caKey := LoadAndParseCACertificates(caKeyPath, caCertPath)
	return &SCIONPilaCertificateSigner{
		caKeyPath:  caKeyPath,
		caCertPath: caCertPath,
		caCert:     caCert,
		caKey:      caKey,
	}
}

func (s *SCIONPilaCertificateSigner) IssueAndSignCertificate(scionAddress string) *SCIONPilaSignedCertificate {

	// Generate client certificate
	clientCertPEM, clientKeyPEM := createClientCertificate(scionAddress, s.caCert, s.caKey)

	// Concatenate client certificate with CA certificate to form the full certificate chain
	fullCertChainPEM := append(clientCertPEM, s.caCert.Raw...)

	return &SCIONPilaSignedCertificate{
		CertificateChain: fullCertChainPEM,
		PrivateKey:       clientKeyPEM,
	}
}

func (s *SCIONPilaCertificateSigner) SignCertificateRequest(scionAddress, certificateSigningRequest string) *SCIONPilaSignedCertificateRequest {

	// TODO: Use csr to issue certificate
	clientCertPEM, _ := createClientCertificate(scionAddress, s.caCert, s.caKey)

	// Concatenate client certificate with CA certificate to form the full certificate chain
	fullCertChainPEM := append(clientCertPEM, s.caCert.Raw...)

	return &SCIONPilaSignedCertificateRequest{
		CertificateChain: fullCertChainPEM,
	}
}

func createClientCertificate(scionAddress string, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) ([]byte, []byte) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(24 * time.Hour)

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		panic(err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: scionAddress,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{scionAddress},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, &priv.PublicKey, caKey)
	if err != nil {
		panic(err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		panic(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})

	return certPEM, keyPEM
}
