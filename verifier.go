package scionpila

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"sort"
	"time"

	"github.com/netsys-lab/scion-pila/pkg/fileutils"
	"github.com/netsys-lab/scion-pila/pkg/pcrypt"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
)

type SCIONPilaCertificateVerifier struct {
	trcFolder string
	isd       int
}

func NewSCIONPilaCertificateVerifier(trcFolder string, isd int) *SCIONPilaCertificateVerifier {
	return &SCIONPilaCertificateVerifier{
		trcFolder: trcFolder,
		isd:       isd,
	}
}

func (v *SCIONPilaCertificateVerifier) VerifyCertificate(certificateFile string, scionAddress string) error {

	// Read certficate file as string

	bts, err := ioutil.ReadFile(certificateFile)
	if err != nil {
		return fmt.Errorf("failed to read certificate file: %s", err.Error())
	}

	// Load certificate chain from file
	chain, err := pcrypt.ParsePEMCerts(string(bts))
	if err != nil {
		return fmt.Errorf("failed to read certificate chain: %s", err.Error())
	}

	if len(chain) != 3 {
		return fmt.Errorf("chain has invalid length: %d, expected: 3", len(chain))
	}

	fmt.Println("DNS NAMES")
	fmt.Println(chain[0].DNSNames)

	// Check if the certificate chain contains the SCION address
	dnsNameMatch := false
	for _, dnsName := range chain[0].DNSNames {
		if dnsName == scionAddress {
			dnsNameMatch = true
			break
		} else {
		}
	}

	if !dnsNameMatch {
		return fmt.Errorf("certificate chain does not contain SCION address: %s", scionAddress)
	}

	//fmt.Println("Certificate Chain:")
	//for i, cert := range chain {
	//	fmt.Printf("Certificate %d:\n", i+1)
	//	fmt.Printf("  Subject: %s\n", cert.Subject.CommonName)
	//}

	//fmt.Println("Certificate chain: ", chain)

	trcFiles, err := fileutils.ListFilesByPrefixAndSuffix(v.trcFolder, fmt.Sprintf("ISD%d-", v.isd), ".trc")
	if err != nil {
		return fmt.Errorf("failed to list TRC files: %s", err.Error())
	}

	sort.Strings(sort.StringSlice(trcFiles))
	trcId := trcFiles[len(trcFiles)-1]

	fmt.Println("Comparing against trc file: ", trcId)

	trc, err := loadTRC(trcId)
	if err != nil {
		return err
	}

	opts := cppki.VerifyOptions{TRC: []*cppki.TRC{&trc.TRC}}
	/*if flags.unixTime != 0 {
		opts.CurrentTime = time.Unix(flags.unixTime, 0)
	}

	if flags.subjectIA != "" {
		expected, err := addr.ParseIA(flags.subjectIA)
		if err != nil {
			return serrors.New("invalid ISD-AS provided for the ISD-AS property check",
				"err", err)
		}
		actual, err := cppki.ExtractIA(chain[0].Subject)
		if err != nil {
			return serrors.New("failed to extract IA from leaf certificate",
				"err", err)
		}
		if actual != expected {
			return serrors.New("ISD-AS property not matching the subject "+
				"in the leaf certificate",
				"expected", expected,
				"actual", actual)
		}
	}*/

	if err := VerifyChain(chain, opts); err != nil {
		return fmt.Errorf("verification failed %s", err)
	}

	fmt.Printf("Successfully verified certificate chain: %q\n", certificateFile)
	return nil
}

// ValidateChain validates that a slice of SCION certificates can be
// a valid chain.
func ValidateChain(certs []*x509.Certificate) error {
	if len(certs) != 3 {
		return fmt.Errorf("chain must contain three certificates")
	}

	for i, cert := range certs {
		if _, err := cppki.ValidateCert(cert); err != nil {
			return fmt.Errorf("validating certificate %d: %s", i, err.Error())
		}
	}

	leaf := certs[0]
	as := certs[1]
	ca := certs[2]
	asValidPeriod := cppki.Validity{NotBefore: as.NotBefore, NotAfter: as.NotAfter}
	caValidPeriod := cppki.Validity{NotBefore: ca.NotBefore, NotAfter: ca.NotAfter}
	leafValidPeriod := cppki.Validity{NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter}

	if !caValidPeriod.Covers(asValidPeriod) {
		return fmt.Errorf("CA validity period does not cover AS period")
	}

	if !asValidPeriod.Covers(leafValidPeriod) {
		return fmt.Errorf("AS validity period does not cover leaf period")
	}

	return nil
}

// VerifyChain attempts to verify the certificate chain against every TRC
// included in opts. Success (nil error) is returned if at least one verification
// succeeds. If all verifications fail, an error containing the details of why
// each verification failed is returned.
//
// The certificate chain is verified by building a trust root based on the Root
// Certificates in each TRC, and searching for a valid verification path.
func VerifyChain(certs []*x509.Certificate, opts cppki.VerifyOptions) error {
	for _, trc := range opts.TRC {
		if err := verifyChain(certs, trc, opts.CurrentTime); err != nil {
			return err
		} else {
			return nil
		}
	}
	return nil
}

func verifyChain(certs []*x509.Certificate, trc *cppki.TRC, now time.Time) error {
	if err := ValidateChain(certs); err != nil {
		return fmt.Errorf("chain validation failed %s", err.Error())
	}
	if trc == nil || trc.IsZero() {
		return fmt.Errorf("TRC required for chain verification")
	}

	leaf := certs[0]
	as := certs[1]
	ca := certs[2]

	// Put CA certificate into the intermediate pool
	intPool := x509.NewCertPool()
	intPool.AddCert(ca)

	rootPool, err := trc.RootPool()
	if err != nil {
		return fmt.Errorf("failed to extract root certs %s", err.Error())
	}

	// Verify that the AS certificate is a proper control plane certificate
	_, err = as.Verify(x509.VerifyOptions{
		Intermediates: intPool,
		Roots:         rootPool,
		KeyUsages:     as.ExtKeyUsage,
		CurrentTime:   now,
	})

	if err != nil {
		return fmt.Errorf("verification of AS control plane cert failed %s", err.Error())
	}

	// Ensure that the parent certificate is the issuer of the child certificate
	success := isParentCert(as, leaf)
	if !success {
		return fmt.Errorf("parent certificate is not issuer of child certificate")
	}

	return err
}

// isParentCert verifies if parentCert is the issuer of childCert
func isParentCert(parentCert, childCert *x509.Certificate) bool {
	// Check if the issuer of the child matches the subject of the parent
	fmt.Println("Parent: ", parentCert.Subject.String())
	fmt.Println("Child: ", childCert.Issuer.String())
	if parentCert.Subject.String() != childCert.Issuer.String() {
		return false
	}

	// Attempt to verify the child's signature with the parent's public key
	// Manually verify the signature of childCert using parentCert's public key
	err := parentCert.CheckSignature(childCert.SignatureAlgorithm, childCert.RawTBSCertificate, childCert.Signature)
	fmt.Println(err)
	return err == nil
}

func loadTRC(trcFile string) (cppki.SignedTRC, error) {
	raw, err := os.ReadFile(trcFile)
	block, _ := pem.Decode(raw)
	if block != nil && block.Type == "TRC" {
		raw = block.Bytes
	}
	if err != nil {
		return cppki.SignedTRC{}, fmt.Errorf("reading TRC %s", err.Error())
	}
	return cppki.DecodeSignedTRC(raw)
}
