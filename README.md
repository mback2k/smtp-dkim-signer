smtp-dkim-signer
================
This Go program is a SMTP-proxy that DKIM-signs e-mails
before submission to an upstream SMTP-server.

[![Build Status](https://travis-ci.org/mback2k/smtp-dkim-signer.svg?branch=master)](https://travis-ci.org/mback2k/smtp-dkim-signer)
[![GoDoc](https://godoc.org/github.com/mback2k/smtp-dkim-signer?status.svg)](https://godoc.org/github.com/mback2k/smtp-dkim-signer)

Dependencies
------------
Special thanks to [@emersion](https://github.com/emersion) for creating and providing
the following Go libraries that are the main building blocks of this program:

- https://github.com/emersion/go-smtp
- https://github.com/emersion/go-smtp-proxy
- https://github.com/emersion/go-dkim

License
-------
Copyright (C) 2018  Marc Hoersken <info@marc-hoersken.de>

This software is licensed as described in the file LICENSE, which
you should have received as part of this software distribution.

All trademarks are the property of their respective owners.
