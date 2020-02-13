/*
	smtp-dkim-signer - SMTP-proxy that DKIM-signs e-mails before submission.
	Copyright (C) 2018 - 2020, Marc Hoersken <info@marc-hoersken.de>

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

package main

import (
	"runtime"

	"github.com/heroku/rollrus"
	"github.com/rollbar/rollbar-go"
	"github.com/rollbar/rollbar-go/errors"

	smtp "github.com/emersion/go-smtp"
	log "github.com/sirupsen/logrus"
)

func setupServer(cfg *config) (*smtp.Server, bool) {
	log.Infof("Creating backends on %s", cfg.Domain)
	be, err := makeBackend(cfg)
	if err != nil {
		panic(err)
	}

	log.Info("VirtualHost overview:")
	for _, vh := range be.VHosts {
		log.Info(vh.Description)
	}

	server := makeServer(cfg, be)
	if cfg.LetsEncrypt.Agreed {
		server.TLSConfig, err = makeTLSConfig(cfg)
		if err != nil {
			panic(err)
		}
	}
	return server, cfg.UseSMTPS
}

func main() {
	log.Info("Loading configuration")
	cfg, err := loadConfig()
	if err != nil {
		log.Fatal(err)
	}

	if cfg.Logging != nil && cfg.Logging.Level != "" {
		l, err := log.ParseLevel(cfg.Logging.Level)
		if err != nil {
			log.Fatal(err)
		}
		log.SetLevel(l)
	}

	if cfg.Rollbar != nil && cfg.Rollbar.AccessToken != "" {
		rollbar.SetStackTracer(errors.StackTracer)
		rollrus.SetupLogging(cfg.Rollbar.AccessToken, cfg.Rollbar.Environment)
		defer rollrus.ReportPanic(cfg.Rollbar.AccessToken, cfg.Rollbar.Environment)
		log.Warn("Errors will be reported to rollbar.com!")
	}

	log.Info("Configuring server")
	server, smtps := setupServer(cfg)

	runtime.GC()

	if err := runServer(server, smtps); err != nil {
		panic(err)
	}
}
