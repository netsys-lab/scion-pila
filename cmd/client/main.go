package main

import (
	"crypto/x509"
	"log"

	flags "github.com/jessevdk/go-flags"
	scionpila "github.com/netsys-lab/scion-pila"
)

var opts struct {

	// Example of a required flag
	Server string `short:"s" long:"server" description:"PILA Server Address for HTTPS communication" default:"" required:"true"`

	// Example of a required flag
	ScionAddress string `short:"a" long:"address" description:"SCION Address to obtain certificate for" default:"" required:"true"`
}

func main() {

	_, err := flags.Parse(&opts)
	if err != nil {
		panic(err)
	}

	client := scionpila.NewSCIONPilaClient(opts.Server)

	// Fetch certificate and private key pair
	certificate, key, err := client.FetchCertificateAndPrivateKey(opts.ScionAddress)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Certificate: %v\n", certificate)
	log.Printf("Key: %v\n", key)

	// Fetch certificate from signing request
	req := &x509.CertificateRequest{
		// Fill data here, create the request with private/public key pair
	}

	certificate, err = client.FetchCertificateFromSigningRequest(opts.ScionAddress, req)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Certificate: %v\n", certificate)

}
