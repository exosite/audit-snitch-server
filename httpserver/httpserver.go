package httpserver

import (
	"log"
	"fmt"
	"time"
	"io"
	"io/ioutil"
	"net/http"
	"errors"
	"math/big"
	"crypto/rand"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/pem"

	"github.com/gin-gonic/gin"
)

var (
	approvedClientKeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment | x509.KeyUsageKeyEncipherment
	ErrBadPublicKeyAlgorithm = errors.New("Only ECDSA keys are supported.")
	ErrInvalidCSRInternalSignature = errors.New("Invalid CSR internal signature")
	ErrMultipleCerts = errors.New("More than one certificate where one was expected")
	Day = time.Hour * 24
	Year = Day * 365
)

type HttpServer struct {
	apiKey []byte
	privateKey *ecdsa.PrivateKey
	publicCert *x509.Certificate
}

func ecKeyFromPem(pemData []byte) (*ecdsa.PrivateKey, []byte, error) {
	keyBlock, remaining := pem.Decode(pemData)
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, remaining, err
	}
	return key, remaining, nil
}

func certFromPem(pemData []byte) (*x509.Certificate, []byte, error) {
	certBlock, remaining := pem.Decode(pemData)
	crt, err := x509.ParseCertificates(certBlock.Bytes)
	if err != nil {
		return nil, remaining, err
	}
	if len(crt) > 1 {
		return nil, remaining, ErrMultipleCerts
	}
	return crt[0], remaining, nil
}

func csrFromPem(pemData []byte) (*x509.CertificateRequest, []byte, error) {
	csrBlock, remaining := pem.Decode(pemData)
	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		return nil, remaining, err
	}
	return csr, remaining, err
}

func New(apiKey []byte, privateKeyPath, publicCertPath string) (*HttpServer, error) {
	privateKeyBytes, err := ioutil.ReadFile(privateKeyPath)
	if err != nil {
		return nil, err
	}
	privateKey, _, err := ecKeyFromPem(privateKeyBytes)
	if err != nil {
		return nil, err
	}

	publicCertBytes, err := ioutil.ReadFile(publicCertPath)
	if err != nil {
		return nil, err
	}
	publicCert, _, err := certFromPem(publicCertBytes)
	if err != nil {
		return nil, err
	}

	return &HttpServer{
		apiKey: apiKey,
		privateKey: privateKey,
		publicCert: publicCert,
	}, nil
}

func (self *HttpServer) certFromCsr(csr *x509.CertificateRequest) (*x509.Certificate, error) {
	if csr.PublicKeyAlgorithm != x509.ECDSA {
		return nil, ErrBadPublicKeyAlgorithm
	}
	names := pkix.Name{
		CommonName: csr.Subject.CommonName,
	}
	now := time.Now()
	return &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: names,
		NotBefore: now.Add(-10 * time.Minute).UTC(),
		NotAfter: now.Add(3 * Year).UTC(),
		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
		PublicKey: csr.PublicKey,
		BasicConstraintsValid: true,
		IsCA: false,
		MaxPathLen: 0,
		MaxPathLenZero: false,
		KeyUsage: approvedClientKeyUsage,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageEmailProtection},
	}, nil
}

func (self *HttpServer) computeHmac(data []byte) []byte {
	h := hmac.New(sha256.New, self.apiKey)
	h.Write(data)
	return h.Sum(nil)
}

func (self *HttpServer) createCert(csr *x509.CertificateRequest) ([]byte, error) {
	if csr.CheckSignature() != nil {
		return nil, ErrInvalidCSRInternalSignature
	}

	clientCert, err := self.certFromCsr(csr)
	if err != nil {
		return nil, err
	}

	return x509.CreateCertificate(rand.Reader, clientCert, self.publicCert, clientCert.PublicKey, self.privateKey)
}

func (self *HttpServer) v1Provision(c *gin.Context) {
	r := c.Request
	if r.Body == nil {
		c.String(http.StatusBadRequest, "No CSR")
		return
	}
	defer r.Body.Close()
	// 8K is probably overly generous.
	lr := &io.LimitedReader{R: r.Body, N: 8 * 1024}
	bodyBytes, err := ioutil.ReadAll(lr)
	if err != nil {
		// Returning anything is probably futile, since the
		// connection probably died.  Let's try anyway!
		c.String(http.StatusBadRequest, "Failed to read CSR")
		return
	}

	csrSigStr := c.Request.Header.Get("CSR-Signature")
	if csrSigStr == "" {
		c.String(http.StatusBadRequest, "No CSR signature")
		return
	}

	csrSig, err := base64.StdEncoding.DecodeString(csrSigStr)
	if err != nil {
		c.String(http.StatusBadRequest, "Invalid CSR external signature")
		return
	}

	hmacSig := self.computeHmac(bodyBytes)
	if !hmac.Equal(hmacSig, csrSig) {
		c.String(http.StatusBadRequest, "Invalid CSR external signature")
		return
	}

	csr, _, err := csrFromPem(bodyBytes)
	if err != nil {
		log.Println(err.Error())
		c.String(http.StatusBadRequest, "Malformed CSR")
		return
	}

	asn1Cert, err := self.createCert(csr)
	if err != nil {
		c.String(http.StatusInternalServerError, "Failed to sign client certificate: %s", err.Error())
		return
	}

	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: asn1Cert})

	c.Data(http.StatusOK, "application/octet-stream", pemCert)
}

func (self *HttpServer) Run(listenPort int, certFile string, keyFile string) {
	r := gin.Default()
	v1 := r.Group("/v1")
	v1.PUT("/provision", self.v1Provision)
	r.RunTLS(fmt.Sprintf(":%d", listenPort), certFile, keyFile)
}
