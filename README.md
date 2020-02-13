smtp-dkim-signer
================
This Go program is a SMTP-proxy that DKIM-signs e-mails
before submission to an upstream SMTP-server.

[![Build Status](https://travis-ci.org/mback2k/smtp-dkim-signer.svg?branch=master)](https://travis-ci.org/mback2k/smtp-dkim-signer)
[![GoDoc](https://godoc.org/github.com/mback2k/smtp-dkim-signer?status.svg)](https://godoc.org/github.com/mback2k/smtp-dkim-signer)
[![Go Report Card](https://goreportcard.com/badge/github.com/mback2k/smtp-dkim-signer)](https://goreportcard.com/report/github.com/mback2k/smtp-dkim-signer)

Dependencies
------------
Special thanks to [@emersion](https://github.com/emersion) for creating and providing
the following Go libraries that are the main building blocks of this program:

- https://github.com/emersion/go-smtp
- https://github.com/emersion/go-smtp-proxy
- https://github.com/emersion/go-dkim

Additional dependencies are the following awesome Go libraries:

- https://github.com/mholt/certmagic
- https://github.com/spf13/viper

Installation
------------
You basically have two options to install this Go program package:

1. If you have Go installed and configured on your PATH, just do the following go get inside your GOPATH to get the latest version:

```
go get -u github.com/mback2k/smtp-dkim-signer
```

2. If you do not have Go installed and just want to use a released binary,
then you can just go ahead and download a pre-compiled Linux amd64 binary from the [Github releases](https://github.com/mback2k/smtp-dkim-signer/releases).

Finally put the smtp-dkim-signer binary onto your PATH and make sure it is executable.

Configuration
-------------
The following YAML file is an example configuration with one virtual host:

```
Address: "localhost:25"
Domain: "localhost"
LetsEncrypt:
  Agreed: true
  Contact: your-name@your-domain.tld
  Challenge: http
  ChallengePort: 80
VirtualHosts:
  - Domain: your-domain.tld
    Upstream: "your-upstream-smtp:465"
    Selector: "your-dkim-selector"
    PrivKeyPath: "your-private-key-file" OR |
      your-private-key-data
    HeaderCan: "relaxed"
    BodyCan: "simple"
HeaderKeys:
  - "From"
  - "Reply-To"
  - "Subject"
  - "Date"
  - "To"
  - "Cc"
  - "In-Reply-To"
  - "References"
  - "Message-ID"
  - "Resent-Date"
  - "Resent-From"
  - "Resent-To"
  - "Resent-Cc"
# optional:
Rollbar:
  AccessToken: "your-rollbar-access-token"
  Environment: production
```

Save this file in one of the following locations and run `./smtp-dkim-signer`:

- /etc/smtp-dkim-signer/smtp-dkim-signer.yaml
- $HOME/.smtp-dkim-signer.yaml
- $PWD/smtp-dkim-signer.yaml

License
-------
Copyright (C) 2018 - 2020, Marc Hoersken <info@marc-hoersken.de>

This software is licensed as described in the file LICENSE, which
you should have received as part of this software distribution.

All trademarks are the property of their respective owners.
