package scionpila

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/netsys-lab/scion-pila/pkg/netutils"
	"github.com/netsys-lab/scion-pila/pkg/pcrypt"
)

type SCIONPilaConfig struct {
	CAKeyPath      string   `toml:"ca_key_path"`
	CACertPath     string   `toml:"ca_cert_path"`
	Server         string   `toml:"server"`
	AllowedSubnets []string `toml:"allowed_subnets"`
}

type CertificateRequest struct {
	ScionAddress string `json:"scion_address" binding:"required"`
}

type CertificateSigningRequest struct {
	ScionAddress              string `json:"scion_address" binding:"required"`
	CertificateSigningRequest string `json:"csr" binding:"required"`
}

type CertificateAndKeyResponse struct {
	CertificateChain string `json:"certificate_chain" binding:"required"`
	PrivateKey       string `json:"private_key" binding:"required"`
}

type CertificateResponse struct {
	CertificateChain string `json:"certificate_chain" binding:"required"`
}

type SCIONPilaServer struct {
	Config *SCIONPilaConfig
	router *gin.Engine
	signer *pcrypt.SCIONPilaCertificateSigner
}

func NewSCIONPilaServer(config *SCIONPilaConfig) *SCIONPilaServer {

	s := &SCIONPilaServer{
		Config: config,
		signer: pcrypt.NewSCIONPilaCertificateSigner(config.CAKeyPath, config.CACertPath),
	}

	router := gin.Default()
	// router.POST("/generate-certificate", s.IssueCertificateHandler())
	router.POST("/sign-certificate-request", s.SignCertificateRequestHandler())
	s.router = router

	return s
}

func (s *SCIONPilaServer) Run() error {
	return s.router.Run(s.Config.Server)
}

/*func (s *SCIONPilaServer) IssueCertificateHandler() func(c *gin.Context) {
	return func(c *gin.Context) {

		ip := strings.Split(c.Request.RemoteAddr, ":")[0]
		ipOk, err := netutils.IsIPInSubnets(ip, s.Config.AllowedSubnets)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		var request CertificateRequest
		if err := c.ShouldBindJSON(&request); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		signedCert := s.signer.IssueAndSignCertificate(request.ScionAddress)

		c.JSON(http.StatusOK, CertificateAndKeyResponse{
			CertificateChain: string(signedCert.CertificateChain),
			PrivateKey:       string(signedCert.PrivateKey),
		})
	}
}*/

func (s *SCIONPilaServer) SignCertificateRequestHandler() func(c *gin.Context) {
	return func(c *gin.Context) {

		ip := strings.Split(c.Request.RemoteAddr, ":")[0]
		ipOk, err := netutils.IsIPInSubnets(ip, s.Config.AllowedSubnets)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		if !ipOk {
			c.JSON(http.StatusForbidden, gin.H{"error": "IP not allowed"})
			return
		}

		var request CertificateSigningRequest
		if err := c.ShouldBindJSON(&request); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		signedCert, err := s.signer.SignCertificateRequest(request.ScionAddress, request.CertificateSigningRequest)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		}

		c.JSON(http.StatusOK, CertificateResponse{
			CertificateChain: string(signedCert.CertificateChain),
		})
	}
}
