package main

import (
	"fmt"
	"log"

	"github.com/jessevdk/go-flags"
	scionpila "github.com/netsys-lab/scion-pila"
)

var opts struct {

	// Example of a required flag
	ISD int `short:"i" long:"isd" description:"ISD of the local host" default:"" required:"true"`

	// Example of a required flag
	CertificateChain string `short:"c" long:"cert" description:"Certificate chain to be verified" default:"" required:"true"`

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

	client := scionpila.NewSCIONPilaCertificateVerifier(opts.TRCFolder)
	err = client.VerifyCertificateFile(opts.CertificateChain, opts.ScionAddress)
	if err != nil {
		fmt.Println("Certificate verification failed")
		log.Fatal(err)
	}
	fmt.Println("Certificate verified successfully")
}
