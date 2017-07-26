package dataserver

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
	"os"
	"net"
	"time"
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

type dsLogger struct {
	ErrLogger *log.Entry
	ErrJack *lumberjack.Logger
	MachineLogger *log.Entry
	MachineJack *lumberjack.Logger
	LastRotation time.Time
	PeerName string
}

func (self *DataServer) setupLogging(remoteip, peerName string) *dsLogger {
	now := time.Now()
	// If we have no other information, assume that last rotation happened
	// at the most recent midnight.
	lastRotation := time.Date(
		now.Year(),
		now.Month(),
		now.Day(),
		0, 0, 0, 0, now.Location())

	errorLogFilePath := filepath.Join(self.machineLogsDir, fmt.Sprintf("%s.err", peerName))
	errJack := &lumberjack.Logger{
		Filename: errorLogFilePath,
		MaxSize: 100, // This is in MB.
		MaxBackups: 5,
		MaxAge: 30, // This is in days, but it affects deletion, not rotation.
	}
	errLogbase := &log.Logger{
		Out: errJack,
		Formatter: new(log.TextFormatter),
		Hooks: make(log.LevelHooks),
		Level: log.DebugLevel,
	};
	errLogger := errLogbase.WithFields(log.Fields{
		"remote_ip": remoteip,
	})

	machineLogFilePath := filepath.Join(self.machineLogsDir, fmt.Sprintf("%s.log", peerName))
	machineLogStat, err := os.Stat(errorLogFilePath)
	if err == nil {
		logmtime := machineLogStat.ModTime()
		// Assume it was last rotated at midnight on the day it was last modified.
		lastRotation = time.Date(
			logmtime.Year(),
			logmtime.Month(),
			logmtime.Day(),
			0, 0, 0, 0, logmtime.Location())
	}
	machineJack := &lumberjack.Logger{
		Filename: machineLogFilePath,
		MaxSize: 100, // This is in MB.
		MaxBackups: 5,
		MaxAge: 30, // This is in days, but it affects deletion, not rotation.
	}
	machineLogbase := &log.Logger{
		Out: machineJack,
		Formatter: new(log.TextFormatter),
		Hooks: make(log.LevelHooks),
		Level: log.DebugLevel,
	};
	machineLogger := machineLogbase.WithFields(log.Fields{
		"remote_ip": remoteip,
	})

	return &dsLogger{
		ErrLogger: errLogger,
		ErrJack: errJack,
		MachineLogger: machineLogger,
		MachineJack: machineJack,
		LastRotation: lastRotation,
		PeerName: peerName,
	}
}

func (self *dsLogger) tryRotateLogs() {
	now := time.Now()
	if now.Sub(self.LastRotation) > 24 * time.Hour {
		self.ErrJack.Rotate()
		self.MachineJack.Rotate()
		self.LastRotation = now
		log.Infof("Rotated logs for %s", self.PeerName)
	}
}

func (self *DataServer) handleConnection(conn *tls.Conn) {
	defer conn.Close()

	peerName, err := getMachineName(conn)
	if err != nil {
		log.Errorf("Failed to get machine name: %s", err.Error())
		return
	}

	logger := self.setupLogging(conn.RemoteAddr().String(), peerName)

	// Check if we should rotate logs before we do anything else.
	logger.tryRotateLogs()

	for {
		sizeBytes := make([]byte, 4)
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		bytesRead, err := conn.Read(sizeBytes)
		if err != nil {
			netErr, ok := err.(net.Error)
			if ok && netErr.Timeout() {
				logger.tryRotateLogs()
				continue
			}
			logger.ErrLogger.Errorf("Failed to read message size: %s", err.Error())
			return
		}
		if bytesRead < 4 {
			logger.ErrLogger.Errorf("Only read %d bytes instead of 4", bytesRead)
			return
		}
		messageSize := binary.BigEndian.Uint32(sizeBytes)
		messageBytes := make([]byte, messageSize)
		bytesRead, err = conn.Read(messageBytes)
		if err != nil {
			logger.ErrLogger.Errorf("Failed to read message: %s", err.Error())
			return
		}
		if uint32(bytesRead) < messageSize {
			logger.ErrLogger.Errorf("Expected %d bytes but only read %d", messageSize, bytesRead)
			return
		}

		report := &audit.SnitchReport{}
		err = proto.Unmarshal(messageBytes, report)
		if err != nil {
			logger.ErrLogger.Errorf("Failed to decode report: %s", err.Error())
			return
		}
		switch report.GetMessageType() {
		case 0:
			logger.ErrLogger.Errorf("Client-side error: %s", string(report.GetPayload()))
		case 1:
			err = recordProgramRun(report, logger.MachineLogger)
			if err != nil {
				logger.ErrLogger.Errorf("Failed to record program run report: %s", err.Error())
			}
		default:
			logger.ErrLogger.Errorf("Unknown message type: %d", report.GetMessageType())
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
