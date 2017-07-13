package dataserver

import (
	"os"
	"fmt"
	"io/ioutil"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"strings"
	"errors"
	"path/filepath"

	"github.com/golang/protobuf/proto"
	"github.com/exosite/audit-snitch-server/audit"
	log "github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
)

var (
	ErrNoPeerCertificates = errors.New("Peer did not present any certificates")
	ErrTlsHandshakeFailed = errors.New("TLS Handshake failed")
	ErrMultiplePeerCertificates = errors.New("Peer presented multiple certificates")
)

type DataServer struct {
	keypair *tls.Certificate
	caCerts *x509.CertPool
	tlsConfig *tls.Config
	machineLogsDir string
}

func New(certPath, keyPath, caCertPath, machineLogsDir string) (*DataServer, error) {
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
		machineLogsDir: machineLogsDir,
	}, nil
}

func (self *DataServer) Run(listenPort int) error{
	ln, err := tls.Listen("tcp", fmt.Sprintf(":%d", listenPort), self.tlsConfig)
	if err != nil {
		return err
	}
	defer ln.Close()

	log.Infof("Dataserver is running on port %d", listenPort)
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		tlsconn, ok := conn.(*tls.Conn)
		if !ok {
			conn.Close()
			log.Infoln("Got a non-TLS connection?!?!?!?!?")
			continue
		}
		go self.handleConnection(tlsconn)
	}
}

func getMachineName(conn *tls.Conn) (string, error) {
	state := conn.ConnectionState()
	if !state.HandshakeComplete {
		err := conn.Handshake()
		if err != nil {
			return "", ErrTlsHandshakeFailed
		}
		state = conn.ConnectionState()
	}
	if state.PeerCertificates == nil || len(state.PeerCertificates) == 0 {
		return "", ErrNoPeerCertificates
	}
	if len(state.PeerCertificates) > 1 {
		return "", ErrMultiplePeerCertificates
	}
	return state.PeerCertificates[0].Subject.CommonName, nil
}

func (self *DataServer) handleConnection(conn *tls.Conn) {
	defer conn.Close()

	peerName, err := getMachineName(conn)
	if err != nil {
		log.Errorf("Failed to get machine name: %s", err.Error())
		return
	}

	errorLogFilePath := filepath.Join(self.machineLogsDir, fmt.Sprintf("%s.err", peerName))
	errLogbase := &log.Logger{
		Out: &lumberjack.Logger{
			Filename: errorLogFilePath,
			MaxSize: 100, // This is in MB.
			MaxBackups: 5,
			MaxAge: 1, // This is in days.
		},
		Formatter: new(log.TextFormatter),
		Hooks: make(log.LevelHooks),
		Level: log.DebugLevel,
	};
	errLogger := errLogbase.WithFields(log.Fields{
		"remote_ip": conn.RemoteAddr().String(),
	})

	machineLogFilePath := filepath.Join(self.machineLogsDir, fmt.Sprintf("%s.log", peerName))
	machineLogbase := &log.Logger{
		Out: &lumberjack.Logger{
			Filename: machineLogFilePath,
			MaxSize: 100, // This is in MB.
			MaxBackups: 5,
			MaxAge: 1, // This is in days.
		},
		Formatter: new(log.TextFormatter),
		Hooks: make(log.LevelHooks),
		Level: log.DebugLevel,
	};
	machineLogger := machineLogbase.WithFields(log.Fields{
		"remote_ip": conn.RemoteAddr().String(),
	})

	for {
		sizeBytes := make([]byte, 4)
		bytesRead, err := conn.Read(sizeBytes)
		if err != nil {
			errLogger.Errorf("Failed to read message size: %s", err.Error())
			return
		}
		if bytesRead < 4 {
			errLogger.Errorf("Only read %d bytes instead of 4", bytesRead)
			return
		}
		messageSize := binary.BigEndian.Uint32(sizeBytes)
		messageBytes := make([]byte, messageSize)
		bytesRead, err = conn.Read(messageBytes)
		if err != nil {
			errLogger.Errorf("Failed to read message: %s", err.Error())
			return
		}
		if uint32(bytesRead) < messageSize {
			errLogger.Errorf("Expected %d bytes but only read %d", messageSize, bytesRead)
			return
		}

		report := &audit.SnitchReport{}
		err = proto.Unmarshal(messageBytes, report)
		if err != nil {
			errLogger.Errorf("Failed to decode report: %s", err.Error())
			return
		}
		switch report.GetMessageType() {
		case 0:
			errLogger.Errorf("Client-side error: %s", string(report.GetPayload()))
		case 1:
			err = recordProgramRun(report, machineLogger)
			if err != nil {
				errLogger.Errorf("Failed to record program run report: %s", err.Error())
			}
		default:
			errLogger.Errorf("Unknown message type: %d", report.GetMessageType())
		}
	}
}

func recordProgramRun(report *audit.SnitchReport, logger *log.Entry) error {
	progRun := &audit.ProgramRun{}
	err := proto.Unmarshal(report.GetPayload(), progRun)
	if err != nil {
		return err
	}

	lgr := logger.WithFields(log.Fields{
		"event": "program_run",
		"syscall": progRun.GetSyscall(),
		"success": progRun.GetSuccess(),
		"exit_code": progRun.GetExit(),
		"pid": progRun.GetPid(),
		"uid": progRun.GetUid(),
		"gid": progRun.GetGid(),
		"auid": progRun.GetAuid(),
		"euid": progRun.GetEuid(),
		"egid": progRun.GetEgid(),
		"suid": progRun.GetSuid(),
		"sgid": progRun.GetSgid(),
		"fsuid": progRun.GetFsuid(),
		"fsgid": progRun.GetFsgid(),
		"command": progRun.GetComm(),
		"exe": progRun.GetExe(),
	})

	tty := progRun.GetTty()
	if tty != "" {
		lgr = lgr.WithFields(log.Fields{
			"tty": tty,
		})
	}
	subj := progRun.GetSubj()
	if subj != "" {
		lgr = lgr.WithFields(log.Fields{
			"selinux_subject": subj,
		})
	}

	lgr.Info(strings.Join(progRun.GetArgs(), " "))

	return nil
}
