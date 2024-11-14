package main

import (
	"fmt"
	"log"

	flags "github.com/jessevdk/go-flags"
	scionpila "github.com/netsys-lab/scion-pila"
)

var opts struct {

	// Example of a required flag
	Server string `short:"s" long:"server" description:"PILA Server Address for HTTPS communication" default:"" required:"true"`

	// Example of a required flag
	ScionAddress string `short:"a" long:"address" description:"SCION Address to obtain certificate for" default:"" required:"true"`

	// Example of a required flag
	TRCFolder string `short:"t" long:"trcs" description:"Folder which contains all the SCION TRCs" default:"/etc/scion/certs" required:"false"`

	// Example of a required flag
	//SkipVerification bool `short:"k" long:"skip" description:"Skip certificate verification" default:"false" required:"true"`
}

func main() {

	_, err := flags.Parse(&opts)
	if err != nil {
		panic(err)
	}

	client := scionpila.NewSCIONPilaClient(opts.Server)

	// Fetch certificate and private key pair
	/*certificate, key, err := client.FetchCertificateAndPrivateKey(opts.ScionAddress)
	if err != nil {
		log.Fatal(err)
	}*/

	key := scionpila.NewPrivateKey()
	csr, err := scionpila.NewCertificateSigningRequest(key)
	if err != nil {
		log.Fatal(err)
	}

	certificate, err := client.FetchCertificateFromSigningRequest(opts.ScionAddress, csr)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Certificate: %v\n", certificate)
	log.Printf("Key: %v\n", key)

	verifier := scionpila.NewSCIONPilaCertificateVerifier(opts.TRCFolder)
	err = verifier.VerifyCertificateChain(certificate, opts.ScionAddress)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Certificate verified successfully")

	// Fetch certificate from signing request
	//req := &x509.CertificateRequest{
	// Fill data here, create the request with private/public key pair
	//}

	//certificate, err = client.FetchCertificateFromSigningRequest(opts.ScionAddress, req)
	//if err != nil {
	//	log.Fatal(err)
	//}

	log.Printf("Certificate: %v\n", certificate)

}
