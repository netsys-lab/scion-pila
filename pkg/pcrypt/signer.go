package pcrypt

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"

	"github.com/scionproto/scion/pkg/snet"
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
	asCert *x509.Certificate
	asKey  *ecdsa.PrivateKey
}

func NewSCIONPilaCertificateSigner(caKeyPath, caCertPath string) *SCIONPilaCertificateSigner {
	caCerts, asKey := LoadAndParseCACertificates(caKeyPath, caCertPath)
	return &SCIONPilaCertificateSigner{
		caKeyPath:  caKeyPath,
		caCertPath: caCertPath,
		asCert:     caCerts[0],
		caCert:     caCerts[1],
		asKey:      asKey,
	}
}

/*func (s *SCIONPilaCertificateSigner) IssueAndSignCertificate(scionAddress string) *SCIONPilaSignedCertificate {

	// Generate client certificate
	clientCertPEM, clientKeyPEM := createClientCertificate(scionAddress, s.asCert, s.asKey)
	fmt.Println(string(clientCertPEM))
	// Concatenate client certificate with CA certificate to form the full certificate chain
	asCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.asCert.Raw})
	caCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.caCert.Raw})
	fullCertChainPEM := append(clientCertPEM, asCertPEM...)
	fullCertChainPEM = append(fullCertChainPEM, caCertPEM...)

	fmt.Println(string(fullCertChainPEM))
	return &SCIONPilaSignedCertificate{
		CertificateChain: fullCertChainPEM,
		PrivateKey:       clientKeyPEM,
	}
}*/

func (s *SCIONPilaCertificateSigner) SignCertificateRequest(scionAddress, certificateSigningRequest string) (*SCIONPilaSignedCertificateRequest, error) {

	// Decode the CSR PEM
	block, _ := pem.Decode([]byte(certificateSigningRequest))
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("failed to decode CSR PEM block")
	}

	// Parse the CSR
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSR: %v", err)
	}

	clientCertPEM := signClientCertificateRequest(scionAddress, s.asCert, s.asKey, csr)

	// Concatenate client certificate with CA certificate to form the full certificate chain
	asCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.asCert.Raw})
	caCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.caCert.Raw})
	fullCertChainPEM := append(clientCertPEM, asCertPEM...)
	fullCertChainPEM = append(fullCertChainPEM, caCertPEM...)

	return &SCIONPilaSignedCertificateRequest{
		CertificateChain: fullCertChainPEM,
	}, nil
}

/*func createClientCertificate(scionAddress string, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) ([]byte, []byte) {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		panic(err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(24 * time.Hour)

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		panic(err)
	}

	// Calculate the Subject Key Identifier
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		panic(err)
	}
	subjectKeyID := sha1.Sum(pubKeyBytes)

	customOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 55324, 1, 2, 1}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: scionAddress,
			ExtraNames: []pkix.AttributeTypeAndValue{
				{
					Type:  customOID,
					Value: fmt.Sprintf("%s-%s", "1", "150"),
				},
			},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsage(x509.ExtKeyUsageTimeStamping),
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageTimeStamping},
		BasicConstraintsValid: true,
		DNSNames:              []string{scionAddress},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		SubjectKeyId:          subjectKeyID[:],
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
}*/

func signClientCertificateRequest(scionAddress string, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, csr *x509.CertificateRequest) []byte {

	fmt.Println(scionAddress)
	snetAddr, err := snet.ParseUDPAddr(scionAddress)
	if err != nil {
		panic(fmt.Errorf("failed to parse SCION address: %s", err.Error()))
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(24 * time.Hour)

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		panic(err)
	}

	// Calculate the Subject Key Identifier
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(csr.PublicKey)
	if err != nil {
		panic(err)
	}
	subjectKeyID := sha1.Sum(pubKeyBytes)

	customOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 55324, 1, 2, 1}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: scionAddress,
			ExtraNames: []pkix.AttributeTypeAndValue{
				{
					Type:  customOID,
					Value: fmt.Sprintf("%s-%s", snetAddr.IA.ISD(), snetAddr.IA.AS()),
				},
			},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsage(x509.ExtKeyUsageTimeStamping),
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageTimeStamping},
		BasicConstraintsValid: true,
		DNSNames:              []string{scionAddress},
		IPAddresses:           []net.IP{snetAddr.Host.IP},
		SubjectKeyId:          subjectKeyID[:],
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, csr.PublicKey, caKey)
	if err != nil {
		panic(err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	return certPEM
}
