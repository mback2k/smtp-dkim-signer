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
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	dkim "github.com/emersion/go-dkim"
	smtp "github.com/emersion/go-smtp"
	smtpproxy "github.com/emersion/go-smtp-proxy"
	backendutil "github.com/emersion/go-smtp/backendutil"
	"github.com/spf13/viper"
)

var (
	// ErrAuthFailed Error for authentication failure
	ErrAuthFailed = errors.New("Authentication failed")
)

var defaultHeaderKeys = []string{
	"From", "Reply-To", "Subject", "Date", "To", "Cc",
	"In-Reply-To", "References", "Message-ID",
	"Resent-Date", "Resent-From", "Resent-To", "Resent-Cc",
	"List-Id", "List-Help", "List-Unsubscribe", "List-Subscribe",
	"List-Post", "List-Owner", "List-Archive",
}

type configVHost struct {
	Domain      string
	Upstream    string
	Selector    string
	PrivKeyPath string
	HeaderCan   string
	BodyCan     string
	HeaderKeys  []string
}

type config struct {
	Address         string
	Domain          string
	MaxIdleSeconds  int
	MaxMessageBytes int
	MaxRecipients   int
	VirtualHosts    []*configVHost
	HeaderKeys      []string
}

type backendVHost struct {
	TransBe *backendutil.TransformBackend
	ProxyBe *smtpproxy.Backend
	DkimOpt *dkim.SignOptions
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

func makeOptions(cfg *config, cfgvh *configVHost) (*dkim.SignOptions, error) {
	if cfg == nil || cfgvh == nil {
		return nil, fmt.Errorf("this should never happen")
	}
	if cfgvh.Domain == "" {
		return nil, fmt.Errorf("no VirtualHost.Domain specified")
	}
	if cfgvh.Selector == "" {
		return nil, fmt.Errorf("no VirtualHost.Selector specified")
	}
	if cfgvh.PrivKeyPath == "" {
		return nil, fmt.Errorf("no VirtualHost.PrivKeyPath specified")
	}

	if len(cfgvh.HeaderKeys) == 0 {
		cfgvh.HeaderKeys = cfg.HeaderKeys
	}

	privkey, err := loadPrivKey(cfgvh.PrivKeyPath)
	if err != nil {
		return nil, fmt.Errorf("unable to load VirtualHost.PrivKeyPath due to: %s", err)
	}

	dkimopt := &dkim.SignOptions{
		Domain:                 cfgvh.Domain,
		Selector:               cfgvh.Selector,
		Signer:                 privkey,
		Hash:                   crypto.SHA256,
		HeaderCanonicalization: cfgvh.HeaderCan,
		BodyCanonicalization:   cfgvh.BodyCan,
		HeaderKeys:             cfgvh.HeaderKeys,
	}
	return dkimopt, nil
}

func main() {
	viper.SetDefault("MaxIdleSeconds", 300)
	viper.SetDefault("MaxMessageBytes", 10240000)
	viper.SetDefault("MaxRecipients", 50)
	viper.SetDefault("HeaderKeys", defaultHeaderKeys)
	viper.SetConfigName("smtp-dkim-signer")
	viper.AddConfigPath("/etc/smtp-dkim-signer/")
	viper.AddConfigPath("$HOME/.smtp-dkim-signer")
	viper.AddConfigPath(".")
	err := viper.ReadInConfig()
	if err != nil {
		log.Fatal(err)
	}

	var cfg config
	err = viper.GetViper().UnmarshalExact(&cfg)
	if err != nil {
		log.Fatal(err)
	}

	var be backend
	be.VHosts = make(map[string]*backendVHost)
	for idx, cfgvh := range cfg.VirtualHosts {
		log.Printf("VirtualHost #%d: Validating options", idx)

		dkimopt, err := makeOptions(&cfg, cfgvh)
		if err != nil {
			log.Fatal(err)
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

	s := smtp.NewServer(&be)
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
