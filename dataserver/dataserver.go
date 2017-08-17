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

type DsRecords map[string][]int

type dsRecordKeeperOp struct {
	op int
	name string
	port int
	resp chan DsRecords
}

func addRecordOp(name string, port int) *dsRecordKeeperOp {
	return &dsRecordKeeperOp{
		op: 1,
		name: name,
		port: port,
		resp: nil,
	}
}

func rmRecordOp(name string, port int) *dsRecordKeeperOp {
	return &dsRecordKeeperOp{
		op: 2,
		name: name,
		port: port,
		resp: nil,
	}
}

func dumpRecordOp(resp chan DsRecords) *dsRecordKeeperOp {
	return &dsRecordKeeperOp{
		op: 3,
		name: "",
		port: 0,
		resp: resp,
	}
}

func (self *dsRecordKeeperOp) Apply(records DsRecords) DsRecords {
	switch self.op {
	case 1:
		rec, ok := records[self.name]
		if !ok {
			rec = make([]int, 0)
		}
		records[self.name] = append(rec, self.port)
		return records
	case 2:
		rec, ok := records[self.name]
		if !ok {
			return records
		}

		// If there's only one record (usual case),
		// just delete the whole thing if the port
		// matches.
		if len(rec) == 1 {
			if rec[0] == self.port {
				delete(records, self.name)
				return records
			} else {
				return records
			}
		}

		// There's more than one record, so find the one
		// where the port matches and nuke it.
		target := -1
		for i, v := range rec {
			if v == self.port {
				target = i
			}
		}
		if target == -1 {
			return records
		}
		rec = append(rec[:target], rec[target+1:]...)
		records[self.name] = rec
		return records
	case 3:
		newMap := make(DsRecords)
		for k, v := range records {
			newV := make([]int, len(v))
			copy(newV, v)
			newMap[k] = newV
		}
		self.resp <- newMap
		return records
	default:
		return records
	}
}

type dsRecordKeeper struct {
	records DsRecords
	opChan chan *dsRecordKeeperOp
}

func newDsRecordKeeper() *dsRecordKeeper {
	rk := &dsRecordKeeper{
		records: make(DsRecords),
		opChan: make(chan *dsRecordKeeperOp, 100),
	}
	go rk.mainloop()

	return rk
}

func (self *dsRecordKeeper) mainloop() {
	for op := range self.opChan {
		self.records = op.Apply(self.records)
	}
}

func (self *dsRecordKeeper) Close() {
	close(self.opChan)
}

func (self *dsRecordKeeper) AddRecord(name string, port int) {
	self.opChan <- addRecordOp(name, port)
}

func (self *dsRecordKeeper) RmRecord(name string, port int) {
	self.opChan <- rmRecordOp(name, port)
}

func (self *dsRecordKeeper) DumpRecords() DsRecords {
	resp := make(chan DsRecords)
	self.opChan <- dumpRecordOp(resp)
	recs := <-resp
	return recs
}

type DataServer struct {
	keypair *tls.Certificate
	caCerts *x509.CertPool
	tlsConfig *tls.Config
	machineLogsDir string
	recordKeeper *dsRecordKeeper
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
		recordKeeper: newDsRecordKeeper(),
	}, nil
}

func (self *DataServer) Close() {
	self.recordKeeper.Close()
}

func (self *DataServer) DumpRecords() DsRecords {
	return self.recordKeeper.DumpRecords()
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
		// openssl s_client sends the CA cert along with the client cert.  WTF?
		if state.PeerCertificates[1].Subject.CommonName != state.PeerCertificates[1].Issuer.CommonName {
			return "", ErrMultiplePeerCertificates
		}
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
		if err == ErrMultiplePeerCertificates {
			state := conn.ConnectionState()
			for i, cert := range state.PeerCertificates {
				log.Infof("Cert {}: {} issued by {}", i, cert.Subject.CommonName, cert.Issuer.CommonName)
			}
		}
		return
	}

	remoteAddr := conn.RemoteAddr()
	remoteAddrTcp, ok := remoteAddr.(*net.TCPAddr)
	if !ok {
		log.Errorf("Could not obtain the remote address for connection from %s", peerName)
		return
	}
	remotePort := remoteAddrTcp.Port
	self.recordKeeper.AddRecord(peerName, remotePort)
	defer self.recordKeeper.RmRecord(peerName, remotePort)

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
		case 2:
			log.Debugf("Received keepalive message from client %s", peerName)
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
