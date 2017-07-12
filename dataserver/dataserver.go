package dataserver

import (
	"os"
	"log"
	"fmt"
	"io/ioutil"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"strings"

	"github.com/golang/protobuf/proto"
	"github.com/exosite/audit-snitch-server/audit"
)

func bytesWriter(writer *os.File, input <-chan []byte) {
	for bytes := range input {
		//log.Printf("Writing %d bytes...\n", len(bytes))
		//log.Printf("Text:\n%s\n", string(bytes))
		bytesWritten, err := writer.Write(bytes)
		//log.Printf("Wrote %d bytes\n", bytesWritten)
		if bytesWritten != len(bytes) {
			log.Printf("Only wrote %d out of %d bytes.  Why?\n", bytesWritten, len(bytes))
		}
		if err != nil {
			log.Printf("Failed to write: %s\n", err.Error())
		}
		writer.Sync()
		/*log.Println("Flushing...")
		err = writer.Flush()
		if err != nil {
			log.Println(err.Error())
		}*/
	}
}

type DataServer struct {
	keypair *tls.Certificate
	caCerts *x509.CertPool
	tlsConfig *tls.Config
}

func New(certPath, keyPath, caCertPath string) (*DataServer, error) {
	cer, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}

	clientCertPool := x509.NewCertPool()
	cafile, err := os.Open(caCertPath)
	if err != nil {
		return nil, err
	}
	cacertBytes, err := ioutil.ReadAll(cafile)
	if err != nil {
		return nil, err
	}
	cafile.Close()
	cafile = nil
	clientCertPool.AppendCertsFromPEM(cacertBytes)
	config := &tls.Config{
		Certificates: []tls.Certificate{cer},
		ClientCAs: clientCertPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
	}
	config.BuildNameToCertificate()
	return &DataServer{
		keypair: &cer,
		caCerts: clientCertPool,
		tlsConfig: config,
	}, nil
}

func (self *DataServer) Run(listenPort int) error{
	ln, err := tls.Listen("tcp", fmt.Sprintf(":%d", listenPort), self.tlsConfig)
	if err != nil {
		return err
	}
	defer ln.Close()

	f, err := os.OpenFile("/tmp/server.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0755)
	bytesChan := make(chan []byte)
	go bytesWriter(f, bytesChan)
	defer close(bytesChan)

	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		tlsconn, ok := conn.(*tls.Conn)
		if !ok {
			conn.Close()
			log.Println("Got a non-TLS connection?!?!?!?!?")
			continue
		}
		go handleConnection(tlsconn, bytesChan)
	}
}

func handleConnection(conn *tls.Conn, output chan<- []byte) {
	defer conn.Close()
	log.Printf("Remote IP: %s\n", conn.RemoteAddr().String())
	state := conn.ConnectionState()
	if !state.HandshakeComplete {
		err := conn.Handshake()
		if err != nil {
			log.Printf("Handshake failed: %s\n", err.Error())
			return
		}
		state = conn.ConnectionState()
	}
	if state.PeerCertificates == nil || len(state.PeerCertificates) == 0 {
		log.Println("No peer certificates?  HOW?")
		return
	}
	if len(state.PeerCertificates) > 1 {
		log.Println("Multiple peer certificates!  Using the first one...")
	}
	peerName := state.PeerCertificates[0].Subject.CommonName
	for {
		sizeBytes := make([]byte, 4)
		bytesRead, err := conn.Read(sizeBytes)
		if err != nil {
			log.Printf("Failed to read message size: %s\n", err.Error())
			return
		}
		if bytesRead < 4 {
			log.Printf("Only read %d bytes instead of 4\n", bytesRead)
			return
		}
		messageSize := binary.BigEndian.Uint32(sizeBytes)
		messageBytes := make([]byte, messageSize)
		bytesRead, err = conn.Read(messageBytes)
		if err != nil {
			log.Printf("Failed to read message: %s\n", err.Error())
			return
		}
		if uint32(bytesRead) < messageSize {
			log.Printf("Expected %d bytes but only read %d\n", messageSize, bytesRead)
			return
		}

		report := &audit.SnitchReport{}
		err = proto.Unmarshal(messageBytes, report)
		if err != nil {
			log.Printf("Failed to decode report: %s\n", err.Error())
			return
		}
		switch report.GetMessageType() {
		case 0:
			log.Printf("Client-side error: %s\n", string(report.GetPayload()))
		case 1:
			err = recordProgramRun(peerName, report)
			if err != nil {
				log.Printf("Failed to record program run report: %s\n", err.Error())
			}
		default:
			log.Printf("Unknown message type: %d\n", report.GetMessageType())
		}
	}
}

func recordProgramRun(peerName string, report *audit.SnitchReport) error {
	progRun := &audit.ProgramRun{}
	err := proto.Unmarshal(report.GetPayload(), progRun)
	if err != nil {
		return err
	}

	log.Printf("[%s] Program run: %s\n", peerName, strings.Join(progRun.GetArgs(), " "))

	return nil
}
