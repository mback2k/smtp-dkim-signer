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

	smtp "github.com/emersion/go-smtp"
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
	s.AllowInsecureAuth = true

	log.Println("Starting server at", s.Addr)
	if err := s.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
