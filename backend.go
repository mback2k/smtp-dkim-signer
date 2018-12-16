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
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"strings"
	"time"

	dkim "github.com/emersion/go-dkim"
	smtp "github.com/emersion/go-smtp"
	smtpproxy "github.com/emersion/go-smtp-proxy"
	backendutil "github.com/emersion/go-smtp/backendutil"
)

var (
	// ErrAuthFailed Error for authentication failure
	ErrAuthFailed = errors.New("Authentication failed")
)

type backendVHost struct {
	ByDomain string
	TransBe  *backendutil.TransformBackend
	ProxyBe  *smtpproxy.Backend
	DkimOpt  *dkim.SignOptions
}

type backend struct {
	VHosts map[string]*backendVHost
}

func (bkdvh *backendVHost) Login(username, password string) (smtp.User, error) {
	return bkdvh.ProxyBe.Login(username, password)
}

func (bkdvh *backendVHost) AnonymousLogin() (smtp.User, error) {
	return nil, smtp.ErrAuthRequired
}

func (bkdvh *backendVHost) Transform(from string, to []string, r io.Reader) (string, []string, io.Reader) {
	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()

		var s strings.Builder
		s.WriteString("Received: by ")
		s.WriteString(bkdvh.ByDomain)
		s.WriteString(" (smtp-dkim-signer) with ESMTPSA;")
		s.WriteString("\r\n\t")
		s.WriteString(time.Now().UTC().Format("Mon, 2 Jan 2006 15:04:05 -0700 (MST)"))
		s.WriteString("\r\n")
		pw.Write([]byte(s.String()))

		var b bytes.Buffer
		tr := io.TeeReader(r, &b)
		err := dkim.Sign(pw, tr, bkdvh.DkimOpt)
		if err != nil {
			log.Println(err)
			mr := io.MultiReader(&b, r)
			_, err := io.Copy(pw, mr)
			if err != nil {
				log.Println(err)
			}
		}
	}()
	return from, to, pr
}

func (bkd *backend) Login(username, password string) (smtp.User, error) {
	splits := strings.Split(username, "@")
	if len(splits) < 1 {
		return nil, ErrAuthFailed
	}
	domain := splits[len(splits)-1]
	if len(domain) < 1 {
		return nil, ErrAuthFailed
	}
	bkdvh, found := bkd.VHosts[domain]
	if !found {
		return nil, ErrAuthFailed
	}
	return bkdvh.TransBe.Login(username, password)
}

func (bkd *backend) AnonymousLogin() (smtp.User, error) {
	return nil, smtp.ErrAuthRequired
}

func makeBackend(cfg *config) (*backend, error) {
	var be backend
	be.VHosts = make(map[string]*backendVHost)
	for idx, cfgvh := range cfg.VirtualHosts {
		log.Printf("VirtualHost #%d: Validating options", idx)

		dkimopt, err := makeOptions(cfg, cfgvh)
		if err != nil {
			return nil, err
		}

		vhostbe := &backendVHost{ByDomain: cfg.Domain, DkimOpt: dkimopt}
		vhostbe.ProxyBe = smtpproxy.NewTLS(cfgvh.Upstream, &tls.Config{})
		vhostbe.TransBe = &backendutil.TransformBackend{
			Backend:   vhostbe,
			Transform: vhostbe.Transform,
		}

		be.VHosts[cfgvh.Domain] = vhostbe
		log.Printf("VirtualHost #%d: %s via %s", idx, cfgvh.Domain, cfgvh.Upstream)
	}
	return &be, nil
}