/*
	smtp-dkim-signer - SMTP-proxy that DKIM-signs e-mails before submission.
	Copyright (C) 2018  Marc Hoersken <info@marc-hoersken.de>

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
	"log"
	"strings"

	smtp "github.com/emersion/go-smtp"
	"github.com/mholt/certmagic"
)

func main() {
	log.Println("Loading configuration")
	cfg, err := loadConfig()
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Creating backends on", cfg.Domain)
	be, err := makeBackend(cfg)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("VirtualHost overview:")
	for _, vh := range be.VHosts {
		log.Println(vh.Description)
	}

	s := smtp.NewServer(be)
	s.Addr = cfg.Address
	s.Domain = cfg.Domain
	s.MaxIdleSeconds = cfg.MaxIdleSeconds
	s.MaxMessageBytes = cfg.MaxMessageBytes
	s.MaxRecipients = cfg.MaxRecipients
	s.AllowInsecureAuth = !cfg.Secure

	if !cfg.Secure {
		log.Println(strings.Repeat("-", 60))
		log.Println("WARNING: This server is running in insecure mode!")
		log.Println("CAUTION: Never try to access this server over the internet!")
		log.Println("WARNING: Your credentials would be exposed and unprotected!")
		log.Println(strings.Repeat("-", 60))

		log.Println("Starting insecure SMTP server at", s.Addr)
		if err := s.ListenAndServe(); err != nil {
			log.Fatal(err)
		}
	} else {
		mgc := certmagic.New(certmagic.Config{
			CA:                      certmagic.LetsEncryptProductionCA,
			Email:                   cfg.LetsEncrypt.Contact,
			Agreed:                  cfg.LetsEncrypt.Agreed,
			DisableHTTPChallenge:    cfg.LetsEncrypt.Challenge != "http",
			DisableTLSALPNChallenge: cfg.LetsEncrypt.Challenge != "tls-alpn",
			ListenHost:              cfg.LetsEncrypt.ChallengeHost,
			AltHTTPPort:             cfg.LetsEncrypt.ChallengePort,
			AltTLSALPNPort:          cfg.LetsEncrypt.ChallengePort,
		})

		err := mgc.Manage([]string{cfg.Domain})
		if err != nil {
			log.Fatal(err)
		}

		s.TLSConfig = mgc.TLSConfig()
		log.Println("Starting secure SMTPS server at", s.Addr)
		if err := s.ListenAndServeTLS(); err != nil {
			log.Fatal(err)
		}
	}
}
