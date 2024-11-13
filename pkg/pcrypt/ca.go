package pcrypt

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

func LoadRawCACertificates(key, cert string) ([]*x509.Certificate, []byte) {

	// Read the CA private key
	caKeyPEM, err := ioutil.ReadFile(key)
	if err != nil {
		panic(fmt.Sprintf("Failed to read CA private key: %v", err))
	}

	// Find and read the CA certificate file
	/*caCertFiles, err := filepath.Glob(filepath.Join(cert, "ISD*.pem"))
	if err != nil || len(caCertFiles) == 0 {
		panic(fmt.Sprintf("Failed to find CA certificate file: %v", err))
	}*/
	caCertPEM, err := ioutil.ReadFile(cert /*caCertFiles[0]*/)
	if err != nil {
		panic(fmt.Sprintf("Failed to read CA certificate: %v", err))
	}

	certs, err := ParsePEMCerts(string(caCertPEM))
	if err != nil {
		panic(err)
	}
	fmt.Println("Certificate Chain:")
	for i, cert := range certs {
		fmt.Printf("Certificate %d:\n", i+1)
		fmt.Printf("  Subject: %s\n", cert.Subject.CommonName)
	}

	return certs, caKeyPEM
}

func ParseCA(caCerts []*x509.Certificate, caKeyPEM []byte) ([]*x509.Certificate, *ecdsa.PrivateKey) {

	block, _ := pem.Decode(caKeyPEM)
	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}

	caKey, ok := privateKey.(*ecdsa.PrivateKey)
	if !ok {
		panic("Failed to parse CA private key")
	}

	return caCerts, caKey
}

func LoadAndParseCACertificates(key, cert string) ([]*x509.Certificate, *ecdsa.PrivateKey) {
	caCertPEM, caKeyPEM := LoadRawCACertificates(key, cert)
	return ParseCA(caCertPEM, caKeyPEM)
}
