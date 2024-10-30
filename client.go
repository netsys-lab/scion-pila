package scionpila

import (
	"crypto/ecdsa"
	"crypto/x509"
)

type SCIONPilaClient struct {
	Server string
}

func NewSCIONPilaClient(server string) *SCIONPilaClient {
	return &SCIONPilaClient{
		Server: server,
	}
}

func (c *SCIONPilaClient) FetchCertificateAndPrivateKey(scionAddress string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	return nil, nil, nil
}

func (c *SCIONPilaClient) FetchCertificateFromSigningRequest(scionAddress string, request *x509.CertificateRequest) (*x509.Certificate, error) {
	return nil, nil
}
