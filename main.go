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
	"runtime"

	smtp "github.com/emersion/go-smtp"
)

func setupServer() (*smtp.Server, bool) {
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

	server := makeServer(cfg, be)
	if cfg.LetsEncrypt.Agreed {
		server.TLSConfig, err = makeTLSConfig(cfg)
		if err != nil {
			log.Fatal(err)
		}
	}
	return server, cfg.Secure
}

func main() {
	server, smtps := setupServer()

	runtime.GC()

	if err := runServer(server, smtps); err != nil {
		log.Fatal(err)
	}
}
