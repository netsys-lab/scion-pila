package main

import (
	"log"

	flags "github.com/jessevdk/go-flags"
	scionpila "github.com/netsys-lab/scion-pila"
)

var opts struct {

	// Example of a required flag
	Server string `short:"s" long:"server" description:"Listen Address for HTTPS" default:":8843" required:"false"`

	// Example of a required flag
	CaKeyPath string `short:"k" long:"key" description:"Listen Address for HTTPS" default:"8843" required:"false"`

	// Example of a required flag
	CaCertPath string `short:"c" long:"cert" description:"Listen Address for HTTPS" default:"8843" required:"false"`

	AllowedSubnets []string `short:"a" long:"allowedSubnets" description:"Allow incoming requests for these subnets" required:"false"`
}

func main() {

	_, err := flags.Parse(&opts)
	if err != nil {
		panic(err)
	}

	scionPilaConfig := &scionpila.SCIONPilaConfig{
		Server:         opts.Server,
		CAKeyPath:      opts.CaKeyPath,
		CACertPath:     opts.CaCertPath,
		AllowedSubnets: opts.AllowedSubnets,
	}

	server := scionpila.NewSCIONPilaServer(scionPilaConfig)
	log.Fatal(server.Run())

}
