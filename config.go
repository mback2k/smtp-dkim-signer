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

import "github.com/spf13/viper"

var defaultHeaderKeys = []string{
	"From", "Reply-To", "Subject", "Date", "To", "Cc",
	"In-Reply-To", "References", "Message-ID",
	"Resent-Date", "Resent-From", "Resent-To", "Resent-Cc",
	"List-Id", "List-Help", "List-Unsubscribe", "List-Subscribe",
	"List-Post", "List-Owner", "List-Archive",
}

type configAcmeLe struct {
	Agreed        bool
	Contact       string
	Challenge     string
	ChallengeHost string
	ChallengePort int
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
	Secure          bool
	LetsEncrypt     *configAcmeLe
	MaxIdleSeconds  int
	MaxMessageBytes int
	MaxRecipients   int
	VirtualHosts    []*configVHost
	HeaderKeys      []string
}

func loadConfig() (*config, error) {
	vpr := viper.GetViper()
	vpr.SetDefault("Secure", false)
	vpr.SetDefault("LetsEncrypt.Agreed", false)
	vpr.SetDefault("LetsEncrypt.Challenge", "http")
	vpr.SetDefault("MaxIdleSeconds", 300)
	vpr.SetDefault("MaxMessageBytes", 10240000)
	vpr.SetDefault("MaxRecipients", 50)
	vpr.SetDefault("HeaderKeys", defaultHeaderKeys)
	vpr.SetConfigName("smtp-dkim-signer")
	vpr.AddConfigPath("/etc/smtp-dkim-signer/")
	vpr.AddConfigPath("$HOME/.smtp-dkim-signer")
	vpr.AddConfigPath(".")
	err := vpr.ReadInConfig()
	if err != nil {
		return nil, err
	}

	var cfg config
	err = vpr.UnmarshalExact(&cfg)
	if err != nil {
		return nil, err
	}
	return &cfg, nil
}
