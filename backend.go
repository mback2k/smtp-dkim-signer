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
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	mathrand "math/rand"
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
	Description string
	ByDomain    string
	TransBe     *backendutil.TransformBackend
	ProxyBe     *smtpproxy.Backend
	DkimOpt     *dkim.SignOptions
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

func (bkdvh *backendVHost) generateMessageID() string {
	idbytes := make([]byte, 5)
	idread, err := rand.Read(idbytes)
	if err != nil {
		mathrand.Read(idbytes[idread:])
	}
	return strings.ToUpper(hex.EncodeToString(idbytes))
}

func (bkdvh *backendVHost) writeReceivedHeader(id string, pw *io.PipeWriter) error {
	bw := bufio.NewWriter(pw)
	if _, err := bw.WriteString("Received: by "); err != nil {
		return err
	}
	if _, err := bw.WriteString(bkdvh.ByDomain); err != nil {
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

func (bkdvh *backendVHost) signMessage(from string, to []string, r io.Reader, id string, pw *io.PipeWriter) {
	var b bytes.Buffer
	defer pw.Close()

	log.Printf("Signing message %s from %s to %s", id, from, to)
	bkdvh.writeReceivedHeader(id, pw)

	tr := io.TeeReader(r, &b)
	if err := dkim.Sign(pw, tr, bkdvh.DkimOpt); err == nil {
		log.Printf("Signed message %s from %s to %s", id, from, to)
	} else {
		logerr := fmt.Errorf("unable to sign message %s due to: %s", id, err)
		log.Println(logerr)

		mr := io.MultiReader(&b, r)
		if _, err := io.Copy(pw, mr); err == nil {
			log.Printf("Recovered message %s from %s to %s", id, from, to)
		} else {
			logerr := fmt.Errorf("unable to recover message %s due to: %s", id, err)
			log.Println(logerr)
		}
	}
}

func (bkdvh *backendVHost) Transform(from string, to []string, r io.Reader) (string, []string, io.Reader, error) {
	id := bkdvh.generateMessageID()
	log.Printf("Handling message %s from %s to %s", id, from, to)

	pr, pw := io.Pipe()
	go bkdvh.signMessage(from, to, r, id, pw)

	return from, to, pr, nil
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
		dkimopt, err := makeOptions(cfg, cfgvh)
		if err != nil {
			return nil, fmt.Errorf("unable to setup VirtualHost #%d due to: %s", idx, err)
		}

		vhostbe := &backendVHost{ByDomain: cfg.Domain, DkimOpt: dkimopt}
		vhostbe.Description = fmt.Sprintf("VirtualHost #%d: %s via %s", idx, cfgvh.Domain, cfgvh.Upstream)
		vhostbe.ProxyBe = smtpproxy.NewTLS(cfgvh.Upstream, &tls.Config{})
		vhostbe.TransBe = &backendutil.TransformBackend{
			Backend:   vhostbe,
			Transform: vhostbe.Transform,
		}

		be.VHosts[cfgvh.Domain] = vhostbe
	}
	return &be, nil
}
