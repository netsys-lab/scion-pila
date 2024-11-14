# scion-pila: Pervasive Internet-Wide Low-Latency Authentication implemented for SCION
This repository contains an implementation of the `PILA` design for the SCION Internet architecture. 

Related Papers:
- [Pervasive Internet-Wide Low-Latency Authentication](https://netsec.ethz.ch/publications/papers/kraehenbuehl2021pila.pdf)
- [Ubiquitous Secure Communication in a Future Internet Architecture](https://link.springer.com/article/10.1007/s42979-022-01234-6)

## Overview
This implementation is designed to run on SCION AS infrastructure nodes that have a SCION control plane AS certificate. `scion-pila` offers a `HTTP` server with a single endpoint to obtain an endhost certificate for a SCION address by providing a certificate signing request (CSR). This server stores a list of allowed subnets, requests are only allowed from source IPs out of these subnets. The intended way is to add AS-internal subnets to this list so that only hosts within the AS can access the endpoint. 

The `scion-pila` offers the following features:
- A server that serves the endpoint to issue endhost certificates for SCION addresses.
- A client that generates a CSR and obtains a certificate from the server.
- A verifier that verifies the certificate against the ISDs trust root chain (TRC).
- A sample how to use `scion-pila` to secure QUIC connections based on `quic-go`.

## Usage

## Server
Within your AS on an infrastructure node that has access to a SCION control-plane AS certificate, deploy a scion-pila server. You can run a standalone instance or include it as library code to your application.

### Standalone
```sh
cd cmd/scion-pila
CGO_ENABLED=0 go build
./scion-pila "--server=:8843" "--key=/etc/scion/crypto/as/cp-as.key" "--cert=/etc/scion/crypto/as/ISDX-ASY.pem"
```

### Library
```go
scionPilaConfig := &scionpila.SCIONPilaConfig{
    Server:         opts.Server,
    CAKeyPath:      opts.CaKeyPath,
    CACertPath:     opts.CaCertPath,
    AllowedSubnets: opts.AllowedSubnets,
}

server := scionpila.NewSCIONPilaServer(scionPilaConfig)
log.Fatal(server.Run())
```

## Client

### Standalone
```sh
cd cmd/client
CGO_ENABLED=0 go build
./client "--server=127.0.0.1:8843" "--address=71-2:0:4a,127.0.0.1:445" "--trcs=/etc/scion/certs"
```

### Library
```go
client := scionpila.NewSCIONPilaClient(opts.Server)

key := scionpila.NewPrivateKey()
csr, err := scionpila.NewCertificateSigningRequest(key)
if err != nil {
    log.Fatal(err)
}

certificate, err := client.FetchCertificateFromSigningRequest(opts.ScionAddress, csr)
if err != nil {
    log.Fatal(err)
}


```

## Certificate Verification

### Standalone
```sh
cd cmd/verify
CGO_ENABLED=0 go build
./verify "--cert=./clientcert.pem" "--isd=1" "--address=1-150,127.0.0.1:445"
```

### Library
```go
// Assuming to have TRCs under a folder on your hosts, e.g. /etc/scion/certs
client := scionpila.NewSCIONPilaCertificateVerifier("/etc/scion/certs") 
err := client.VerifyCertificate(certificate, "71-2:0:4a,127.0.0.1:445")
```

## TODOS
- Let PILA Server listen with own certificate on SCION address to ensure that it is trusted???
- TRC verification of certificates
- Create and send csr and issue cert based on this 
