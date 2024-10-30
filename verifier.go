package scionpila

type SCIONPilaCertificateVerifier struct {
	trcFolder string
}

func NewSCIONPilaCertificateVerifier(trcFolder string) *SCIONPilaCertificateVerifier {
	return &SCIONPilaCertificateVerifier{
		trcFolder: trcFolder,
	}
}

func (v *SCIONPilaCertificateVerifier) VerifyCertificate(certificateChain []byte, scionAddress string) error {

	// Find latest TRC

	// Compare host address against certificate

	// Verify certificate chain against TRC

	// Validate certificate chain
	return nil
}
