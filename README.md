# scion-pila: Pervasive Internet-Wide Low-Latency Authentication implemented for SCION

Related Papers:
- Pervasive Internet-Wide Low-Latency Authentication
- Ubiquitous Secure Communication in a Future Internet Architecture

## Status
Currently work in progress, goal is to have a first PoC soon...

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
./client "--server=127.0.0.1:8843" "--address=71-2:0:4a,127.0.0.1:445"
```

### Library
```go
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
```

## Certificate Verification
```go
// Assuming to have TRCs under a folder on your hosts, e.g. /etc/scion/certs
client := scionpila.NewSCIONPilaCertificateVerifier("/etc/scion/certs") 
err := client.VerifyCertificate(certificate, "71-2:0:4a,127.0.0.1:445")

```


## TODOS
- Let PILA Server listen with own certificate on SCION address to ensure that it is trusted???
- TRC verification of certificates
- Create and send csr and issue cert based on this 
