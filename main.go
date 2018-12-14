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
	"crypto"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"io"
	"log"
	"os"

	dkim "github.com/emersion/go-dkim"
	smtp "github.com/emersion/go-smtp"
	smtpproxy "github.com/emersion/go-smtp-proxy"
	backendutil "github.com/emersion/go-smtp/backendutil"
)

var headerKeys = []string{"From", "Reply-To", "Subject", "Date", "To", "Cc",
	"In-Reply-To", "References", "Message-ID",
	"Resent-Date", "Resent-From", "Resent-To", "Resent-Cc",
	"List-Id", "List-Help", "List-Unsubscribe", "List-Subscribe",
	"List-Post", "List-Owner", "List-Archive"}

type flags struct {
	address     string
	upstream    string
	domain      string
	selector    string
	privkeypath string
	headercan   string
	bodycan     string
}

type backend struct {
	Backend *smtpproxy.Backend
	Options *dkim.SignOptions
}

func (bkd *backend) Login(username, password string) (smtp.User, error) {
	return bkd.Backend.Login(username, password)
}

func (bkd *backend) AnonymousLogin() (smtp.User, error) {
	return nil, smtp.ErrAuthRequired
}

func (bkd *backend) Transform(from string, to []string, r io.Reader) (string, []string, io.Reader) {
	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()
		err := dkim.Sign(pw, r, bkd.Options)
		if err != nil {
			log.Println(err)
		}
	}()
	return from, to, pr
}

func parseFlags(flags *flags) {
	flag.StringVar(&((*flags).address), "address", "localhost:1025", "Listening address")
	flag.StringVar(&((*flags).upstream), "upstream", "", "Upstream SMTP-server")
	flag.StringVar(&((*flags).domain), "domain", "", "Domain")
	flag.StringVar(&((*flags).selector), "selector", "", "Selector")
	flag.StringVar(&((*flags).privkeypath), "privkeypath", "", "Path to private key")
	flag.StringVar(&((*flags).headercan), "headercan", "relaxed", "Header canonicalization")
	flag.StringVar(&((*flags).bodycan), "bodycan", "simple", "Body canonicalization")
	flag.Parse()
}

func readFile(filepath string) (*bytes.Buffer, error) {
	var b bytes.Buffer
	f, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	_, err = b.ReadFrom(f)
	if err != nil {
		return nil, err
	}
	return &b, err
}

func loadPrivKey(privkeypath string) (*rsa.PrivateKey, error) {
	b, err := readFile(privkeypath)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b.Bytes())
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return key, err
}

func main() {
	var flags flags
	parseFlags(&flags)

	privkey, err := loadPrivKey(flags.privkeypath)
	if err != nil {
		log.Fatal(err)
	}

	options := &dkim.SignOptions{
		Domain:                 flags.domain,
		Selector:               flags.selector,
		Signer:                 privkey,
		Hash:                   crypto.SHA256,
		HeaderCanonicalization: flags.headercan,
		BodyCanonicalization:   flags.bodycan,
		HeaderKeys:             headerKeys,
	}

	pb := smtpproxy.NewTLS(flags.upstream, &tls.Config{})
	sb := &backend{Backend: pb, Options: options}
	tb := &backendutil.TransformBackend{Backend: sb, Transform: sb.Transform}

	s := smtp.NewServer(tb)
	s.Addr = flags.address
	s.Domain = flags.domain
	s.MaxIdleSeconds = 300
	s.MaxMessageBytes = 10240000
	s.MaxRecipients = 50
	s.AllowInsecureAuth = true

	log.Println("Starting server at", s.Addr)
	if err := s.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
