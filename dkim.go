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
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"strings"

	dkim "github.com/emersion/go-msgauth/dkim"
)

func loadPrivKey(privkeypath string) (*rsa.PrivateKey, error) {
	var block *pem.Block
	privkey := strings.TrimSpace(privkeypath)
	if strings.HasPrefix(privkey, "-----") &&
		strings.HasSuffix(privkey, "-----") {
		block, _ = pem.Decode([]byte(privkey))
	} else {
		splits := strings.Split(privkeypath, "\n")
		filepath := strings.TrimSpace(splits[0])
		bytes, err := ioutil.ReadFile(filepath)
		if err != nil {
			return nil, err
		}
		block, _ = pem.Decode(bytes)
	}
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
		HeaderCanonicalization: dkim.Canonicalization(cfgvh.HeaderCan),
		BodyCanonicalization:   dkim.Canonicalization(cfgvh.BodyCan),
		HeaderKeys:             cfgvh.HeaderKeys,
	}
	return dkimopt, nil
}
