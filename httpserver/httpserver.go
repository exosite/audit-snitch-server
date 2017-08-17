package httpserver

// audit-snitch-server - Monitor admins actions on servers
// Copyright (C) 2017  Exosite
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

import (
	"fmt"
	"time"
	"strconv"
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
	log "github.com/sirupsen/logrus"

	ds "github.com/exosite/audit-snitch-server/dataserver"
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
	dataServer *ds.DataServer
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

func New(apiKey []byte, privateKeyPath, publicCertPath string, dataServer *ds.DataServer) (*HttpServer, error) {
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
		dataServer: dataServer,
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
		log.Errorln("No CSR!")
		c.String(http.StatusBadRequest, "No CSR")
		return
	}
	defer r.Body.Close()
	// 8K is probably overly generous.
	lr := &io.LimitedReader{R: r.Body, N: 8 * 1024}
	bodyBytes, err := ioutil.ReadAll(lr)
	if err != nil {
		log.Errorln(err.Error())
		// Returning anything is probably futile, since the
		// connection probably died.  Let's try anyway!
		c.String(http.StatusBadRequest, "Failed to read CSR")
		return
	}

	csrSigStr := r.Header.Get("CSR-Signature")
	if csrSigStr == "" {
		log.Errorln("No CSR signature")
		c.String(http.StatusBadRequest, "No CSR signature")
		return
	}

	csrSig, err := base64.StdEncoding.DecodeString(csrSigStr)
	if err != nil {
		log.Errorln(err.Error())
		c.String(http.StatusBadRequest, "Invalid CSR external signature")
		return
	}

	hmacSig := self.computeHmac(bodyBytes)
	if !hmac.Equal(hmacSig, csrSig) {
		log.Errorln(err.Error())
		c.String(http.StatusBadRequest, "Invalid CSR external signature")
		return
	}

	csr, _, err := csrFromPem(bodyBytes)
	if err != nil {
		log.Errorln(err.Error())
		c.String(http.StatusBadRequest, "Malformed CSR")
		return
	}

	asn1Cert, err := self.createCert(csr)
	if err != nil {
		log.Errorln(err.Error())
		c.String(http.StatusInternalServerError, "Failed to sign client certificate")
		return
	}

	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: asn1Cert})

	c.Data(http.StatusOK, "application/octet-stream", pemCert)
	log.WithFields(log.Fields{
		"remote_ip": c.ClientIP(),
	}).Infof("Provisioned machine: %s", csr.Subject.CommonName)
}

func abs(n int64) int64 {
	if n < 0 {
		return -n
	}
	return n
}

func (self *HttpServer) v1Clients(c *gin.Context) {
	requestTimestampStr := c.Request.Header.Get("Request-Timestamp")
	if requestTimestampStr == "" {
		c.String(http.StatusBadRequest, "No Request-Timestamp header")
		return
	}

	requestTimestamp, err := strconv.ParseInt(requestTimestampStr, 10, 64)
	if err != nil {
		log.Errorln(err.Error())
		c.String(http.StatusBadRequest, "Invalid Request-Timestamp header")
		return
	}

	utcUnix := time.Now().UTC().Unix()
	log.Infof("UTC Unix timestamp: %d", utcUnix)
	timeSince := abs(utcUnix - requestTimestamp)
	if timeSince > 300 {
		msg := fmt.Sprintf(
			"Too much time (%d seconds) has elapsed since request was sent",
			timeSince,
		)
		log.Errorln(msg)
		c.String(http.StatusBadRequest, msg)
		return
	}

	dtSigStr := c.Request.Header.Get("Timestamp-Signature")
	if dtSigStr == "" {
		log.Errorln(err.Error())
		c.String(http.StatusBadRequest, "No Timestamp-Signature header")
		return
	}

	dtSig, err := base64.StdEncoding.DecodeString(dtSigStr)
	if err != nil {
		log.Errorln(err.Error())
		c.String(http.StatusBadRequest, "Invalid date/time signature")
		return
	}

	hmacSig := self.computeHmac([]byte(requestTimestampStr))
	if !hmac.Equal(hmacSig, dtSig) {
		c.String(http.StatusBadRequest, "Invalid date/time signature")
		return
	}

	c.JSON(http.StatusOK, self.dataServer.DumpRecords())
}

func (self *HttpServer) Run(listenPort int, certFile string, keyFile string) {
	r := gin.Default()
	v1 := r.Group("/v1")
	v1.PUT("/provision", self.v1Provision)
	v1.GET("/clients", self.v1Clients)
	log.Infof("HTTP server is running on port %d", listenPort)
	r.RunTLS(fmt.Sprintf(":%d", listenPort), certFile, keyFile)
}
