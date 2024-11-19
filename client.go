package scionpila

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/netsys-lab/scion-pila/pkg/logger"
	"github.com/netsys-lab/scion-pila/pkg/pcrypt"
)

type SCIONPilaClient struct {
	Server string
}

func NewSCIONPilaClient(server string) *SCIONPilaClient {
	return &SCIONPilaClient{
		Server: server,
	}
}

/*func (c *SCIONPilaClient) FetchCertificateAndPrivateKey(scionAddress string) ([]x509.Certificate, *ecdsa.PrivateKey, error) {
	url := fmt.Sprintf("%s/generate-certificate", c.Server) // http://localhost:8843/generate-certificate

	// Define the payload
	requestData := CertificateRequest{
		ScionAddress: "1-ff00:0:110",
	}

	// Marshal the payload into JSON
	jsonData, err := json.Marshal(requestData)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal JSON: %w", err)
	}

	// Create the request
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set the content type header
	req.Header.Set("Content-Type", "application/json")

	// Execute the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Check the response status
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("unexpected response status: %s", resp.Status)
	}

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Unmarshal the response into the CertificateAndKeyResponse struct
	var certResponse CertificateAndKeyResponse
	if err := json.Unmarshal(body, &certResponse); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	// Print the struct fields
	fmt.Printf("Response Status: %s\n", resp.Status)
	fmt.Printf("Certificate Chain: %s\n", certResponse.CertificateChain)
	fmt.Printf("Private Key: %s\n", certResponse.PrivateKey)

	fmt.Println("Certificate generated successfully")
	return nil, nil, nil
}*/

func (c *SCIONPilaClient) FetchCertificateFromSigningRequest(scionAddress string, csr []byte) ([]*x509.Certificate, error) {
	url := fmt.Sprintf("%s/sign-certificate-request", c.Server) // http://localhost:8843/sign-certificate-request

	// Define the payload
	requestData := CertificateSigningRequest{
		ScionAddress:              scionAddress,
		CertificateSigningRequest: string(csr),
	}

	// Marshal the payload into JSON
	jsonData, err := json.Marshal(requestData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JSON: %w", err)
	}

	// Create the request
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set the content type header
	req.Header.Set("Content-Type", "application/json")

	// Execute the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	// Check the response status
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected response status: %s", resp.Status)
	}

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Unmarshal the response into the CertificateAndKeyResponse struct
	var certResponse CertificateResponse
	if err := json.Unmarshal(body, &certResponse); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	// Print the struct fields
	// fmt.Printf("Response Status: %s\n", resp.Status)
	// fmt.Printf("Certificate Chain: %s\n", certResponse.CertificateChain)

	logger.Log.Debug("Certificate generated successfully")

	chain, err := pcrypt.ParsePEMCerts(certResponse.CertificateChain)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate chain: %w", err)
	}

	return chain, nil
}
