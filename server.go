/*
	smtp-dkim-signer - SMTP-proxy that DKIM-signs e-mails before submission.
	Copyright (C) 2018 - 2019, Marc Hoersken <info@marc-hoersken.de>

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
	"crypto/tls"
	"strings"

	smtp "github.com/emersion/go-smtp"
	"github.com/mholt/certmagic"
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
	return s
}

func makeTLSConfig(cfg *config) (*tls.Config, error) {
	certmagic.Default.CA = certmagic.LetsEncryptProductionCA
	certmagic.Default.Email = cfg.LetsEncrypt.Contact
	certmagic.Default.Agreed = cfg.LetsEncrypt.Agreed
	certmagic.Default.DisableHTTPChallenge = cfg.LetsEncrypt.Challenge != "http"
	certmagic.Default.DisableTLSALPNChallenge = cfg.LetsEncrypt.Challenge != "tls-alpn"
	certmagic.Default.ListenHost = cfg.LetsEncrypt.ChallengeHost
	certmagic.Default.AltHTTPPort = cfg.LetsEncrypt.ChallengePort
	certmagic.Default.AltTLSALPNPort = cfg.LetsEncrypt.ChallengePort
	mgc := certmagic.NewDefault()

	err := mgc.ManageSync([]string{cfg.Domain})
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
		log.Info("Starting SMTPS server at", server.Addr)
		err = server.ListenAndServeTLS()
	} else {
		log.Info("Starting SMTP server at", server.Addr)
		err = server.ListenAndServe()
	}
	return err
}
