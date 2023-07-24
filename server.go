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
	"context"
	"crypto/tls"
	"strings"

	certmagic "github.com/caddyserver/certmagic"
	"github.com/emersion/go-sasl"
	smtp "github.com/emersion/go-smtp"
	log "github.com/sirupsen/logrus"
)

func makeServer(cfg *config, be *backend) *smtp.Server {
	s := smtp.NewServer(be)
	s.Addr = cfg.Address
	s.Domain = cfg.Domain
	s.ReadTimeout = cfg.ReadTimeout
	s.WriteTimeout = cfg.WriteTimeout
	s.MaxMessageBytes = cfg.MaxMessageBytes
	s.MaxRecipients = cfg.MaxRecipients
	s.AllowInsecureAuth = cfg.AllowInsecureAuth
	s.EnableAuth(sasl.Login, func(conn *smtp.Conn) sasl.Server {
		return sasl.NewLoginServer(func(username, password string) error {
			return conn.Session().AuthPlain(username, password)
		})
	})
	return s
}

func makeTLSConfig(cfg *config) (*tls.Config, error) {
	certmagic.DefaultACME.CA = certmagic.LetsEncryptProductionCA
	certmagic.DefaultACME.Email = cfg.LetsEncrypt.Contact
	certmagic.DefaultACME.Agreed = cfg.LetsEncrypt.Agreed
	certmagic.DefaultACME.DisableHTTPChallenge = cfg.LetsEncrypt.Challenge != "http"
	certmagic.DefaultACME.DisableTLSALPNChallenge = cfg.LetsEncrypt.Challenge != "tls-alpn"
	certmagic.DefaultACME.ListenHost = cfg.LetsEncrypt.ChallengeHost
	certmagic.DefaultACME.AltHTTPPort = cfg.LetsEncrypt.ChallengePort
	certmagic.DefaultACME.AltTLSALPNPort = cfg.LetsEncrypt.ChallengePort
	mgc := certmagic.NewDefault()

	err := mgc.ManageSync(context.TODO(), []string{cfg.Domain})
	if err != nil {
		return nil, err
	}

	return mgc.TLSConfig(), nil
}

func runServer(server *smtp.Server, smtps bool) error {
	if server.TLSConfig == nil {
		log.Warn(strings.Repeat("-", 60))
		log.Warn("WARNING: This server is running without a TLS configuration!")
		log.Warn("CAUTION: Never try to access this server over the internet!")
		log.Warn("WARNING: Your unprotected credentials could be exposed!")
		log.Warn(strings.Repeat("-", 60))
	}

	var err error
	if smtps {
		log.Info("Starting SMTPS server at ", server.Addr)
		err = server.ListenAndServeTLS()
	} else {
		log.Info("Starting SMTP server at ", server.Addr)
		err = server.ListenAndServe()
	}
	return err
}
