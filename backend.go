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
	"bufio"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	mathrand "math/rand"

	dkim "github.com/emersion/go-msgauth/dkim"
	smtp "github.com/emersion/go-smtp"
	"github.com/mback2k/smtp-dkim-signer/internal/smtpproxy"
	log "github.com/sirupsen/logrus"
)

var (
	// ErrAuthFailed Error for authentication failure
	ErrAuthFailed = errors.New("Authentication failed")
)

type backendVHost struct {
	Description string
	ByDomain    string
	ProxyBe     *smtpproxy.Backend
	DkimOpt     *dkim.SignOptions
}

type backend struct {
	VHosts map[string]*backendVHost
}

type sessionState struct {
	Session smtp.Session

	backend *backend
	bkdvh   *backendVHost

	from string
	to   []string
}

func (s *sessionState) generateMessageID() string {
	idbytes := make([]byte, 5)
	idread, err := rand.Read(idbytes)
	if err != nil {
		mathrand.Read(idbytes[idread:])
	}
	return strings.ToUpper(hex.EncodeToString(idbytes))
}

func (s *sessionState) writeReceivedHeader(id string, pw *io.PipeWriter) error {
	bw := bufio.NewWriter(pw)
	if _, err := bw.WriteString("Received: by "); err != nil {
		return err
	}
	if _, err := bw.WriteString(s.bkdvh.ByDomain); err != nil {
		return err
	}
	if _, err := bw.WriteString(" (smtp-dkim-signer) with ESMTPSA id "); err != nil {
		return err
	}
	if _, err := bw.WriteString(id); err != nil {
		return err
	}
	if _, err := bw.WriteString(";\r\n\t"); err != nil {
		return err
	}
	dt := time.Now().UTC().Format("Mon, 2 Jan 2006 15:04:05 -0700 (MST)")
	if _, err := bw.WriteString(dt); err != nil {
		return err
	}
	if _, err := bw.WriteString("\r\n"); err != nil {
		return err
	}
	return bw.Flush()
}

func (s *sessionState) signMessage(pw *io.PipeWriter, r io.Reader, id string) {
	log.WithField("message", id).Tracef("Writing header for message %s", id)
	if err := s.writeReceivedHeader(id, pw); err != nil {
		err = fmt.Errorf("unable to write header %s due to: %s", id, err)
		pw.CloseWithError(err)
		return
	}

	log.WithField("message", id).Tracef("Signing message %s", id)
	if err := dkim.Sign(pw, r, s.bkdvh.DkimOpt); err != nil {
		err = fmt.Errorf("unable to sign message %s due to: %s", id, err)
		pw.CloseWithError(err)
		return
	}

	log.WithField("message", id).Tracef("Signed message %s", id)
	pw.Close()
}

func (s *sessionState) Reset() {
	s.from = ""
	s.to = nil
	s.Session.Reset()
}

func (s *sessionState) Mail(from string, opts *smtp.MailOptions) error {
	if s.Session == nil {
		return smtp.ErrAuthRequired
	}
	err := s.Session.Mail(from, opts)
	if err != nil {
		return err
	}
	s.from = from
	return nil
}

func (s *sessionState) Rcpt(to string) error {
	if s.Session == nil {
		return smtp.ErrAuthRequired
	}
	err := s.Session.Rcpt(to)
	if err != nil {
		return err
	}
	if s.to != nil {
		s.to = append(s.to, to)
	} else {
		s.to = []string{to}
	}
	return nil
}

func (s *sessionState) Data(r io.Reader) error {
	if s.Session == nil {
		return smtp.ErrAuthRequired
	}

	id := s.generateMessageID()
	log.WithField("message", id).Infof("Handling message %s from %s to %s", id, s.from, s.to)

	pr, pw := io.Pipe()
	go s.signMessage(pw, r, id)

	err := s.Session.Data(pr)
	if err != nil {
		log.WithField("message", id).WithError(err).Errorf("Handling message %s failed: %s", id, err)
	}

	s.Reset()
	return err
}

func (s *sessionState) Logout() error {
	if s.Session == nil {
		return smtp.ErrAuthRequired
	}
	s.Reset()
	return s.Session.Logout()
}

func (bkd *backend) NewSession(state *smtp.Conn) (smtp.Session, error) {
	return &sessionState{
		backend: bkd,
		// Session and bkdvh are filled in on successful AuthPlain().
	}, nil
}

func (s *sessionState) AuthPlain(username, password string) error {
	splits := strings.Split(username, "@")
	if len(splits) < 1 {
		return ErrAuthFailed
	}
	domain := splits[len(splits)-1]
	if len(domain) < 1 {
		return ErrAuthFailed
	}
	bkdvh, found := s.backend.VHosts[domain]
	if !found {
		log.Infof("Auth failed: domain %q not found", domain)
		return ErrAuthFailed
	}
	s.bkdvh = bkdvh

	session, err := bkdvh.ProxyBe.NewSession(nil)
	if err != nil {
		return err
	}
	if err := session.AuthPlain(username, password); err != nil {
		return err
	}

	s.Session = session
	return nil
}

func makeBackend(cfg *config) (*backend, error) {
	var be backend
	be.VHosts = make(map[string]*backendVHost)
	for idx, cfgvh := range cfg.VirtualHosts {
		dkimopt, err := makeOptions(cfg, cfgvh)
		if err != nil {
			return nil, fmt.Errorf("unable to setup VirtualHost #%d due to: %s", idx, err)
		}

		vhostbe := &backendVHost{ByDomain: cfg.Domain, DkimOpt: dkimopt}
		vhostbe.Description = fmt.Sprintf("VirtualHost #%d: %s via %s", idx, cfgvh.Domain, cfgvh.Upstream)
		vhostbe.ProxyBe = smtpproxy.NewTLS(cfgvh.Upstream, &tls.Config{})

		be.VHosts[cfgvh.Domain] = vhostbe
	}
	return &be, nil
}
