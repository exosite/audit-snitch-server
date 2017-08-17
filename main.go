package main

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
	"io/ioutil"
	"encoding/base64"

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
	"github.com/urfave/cli"
	"gopkg.in/natefinch/lumberjack.v2"
	"github.com/exosite/audit-snitch-server/httpserver"
	"github.com/exosite/audit-snitch-server/dataserver"
)

type DataServerConfig struct {
	ListenPort int `yaml:"port"`
	CertPath string `yaml:"cert_path"`
	KeyPath string `yaml:"key_path"`
	CACertPath string `yaml:"cacert_path"`
	MachineLogsDir string `yaml:"machine_logs_dir"`
}

type HttpServerConfig struct {
	ListenPort int `yaml:"port"`
	CertPath string `yaml:"cert_path"`
	KeyPath string `yaml:"key_path"`
	CACertPath string `yaml:"cacert_path"`
	CAKeyPath string `yaml:"cakey_path"`
	ApiKey string `yaml:"api_key"`
}

type Config struct {
	DataServer DataServerConfig `yaml:"dataserver"`
	HttpServer HttpServerConfig `yaml:"httpserver"`
	LogFilePath string `yaml:"logfile_path"`
	LogLevel string `yaml:"log_level"`
}

func main() {
	app := cli.NewApp()
	app.Name = "audit-snitch-server"
	app.Usage = "Monitor admin commands on servers"
	app.Version = "1.0"
	app.Action = runServer
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "config",
			Value: "/etc/audit-snitch-server.yaml",
			Usage: "Configuration file",
		},
	}
	app.Run(os.Args)
}

func runServer(c *cli.Context) {
	var config Config
	configPath := c.String("config")
	configBytes, err := ioutil.ReadFile(configPath)
	if err != nil {
		panic(err)
	}
	err = yaml.Unmarshal(configBytes, &config)
	if err != nil {
		panic(err)
	}

	switch config.LogLevel {
	case "debug":
		log.SetLevel(log.DebugLevel)
	case "info":
		log.SetLevel(log.InfoLevel)
	case "warn":
		log.SetLevel(log.WarnLevel)
	case "error":
		log.SetLevel(log.ErrorLevel)
	case "fatal":
		log.SetLevel(log.FatalLevel)
	case "panic":
		log.SetLevel(log.PanicLevel)
	default:
		log.SetLevel(log.ErrorLevel)
	}

	log.SetOutput(&lumberjack.Logger{
		Filename: config.LogFilePath,
		MaxSize: 100, // This is in MB.
		MaxBackups: 5,
		MaxAge: 28, // This is in days.
	})

	dataServer, err := dataserver.New(
		config.DataServer.CertPath,
		config.DataServer.KeyPath,
		config.DataServer.CACertPath,
		config.DataServer.MachineLogsDir,
	)
	if err != nil {
		panic(err)
	}

	apiKey, err := base64.StdEncoding.DecodeString(config.HttpServer.ApiKey)
	if err != nil {
		panic(err)
	}
	httpServer, err := httpserver.New(apiKey, config.HttpServer.CAKeyPath, config.HttpServer.CACertPath, dataServer)
	if err != nil {
		panic(err)
	}

	go httpServer.Run(config.HttpServer.ListenPort, config.DataServer.CertPath, config.DataServer.KeyPath)
	panic(dataServer.Run(config.DataServer.ListenPort))
}
