module github.com/mback2k/smtp-dkim-signer

go 1.12

require (
	github.com/emersion/go-msgauth v0.3.1
	github.com/emersion/go-sasl v0.0.0-20190817083125-240c8404624e // indirect
	github.com/emersion/go-smtp v0.11.2
	github.com/emersion/go-smtp-proxy v0.0.0-20190525162413-b8176e451516
	github.com/heroku/rollrus v0.1.1
	github.com/klauspost/cpuid v1.2.1 // indirect
	github.com/magiconair/properties v1.8.1 // indirect
	github.com/mholt/certmagic v0.8.3
	github.com/miekg/dns v1.1.22 // indirect
	github.com/pelletier/go-toml v1.6.0 // indirect
	github.com/rollbar/rollbar-go v1.2.0
	github.com/rollbar/rollbar-go/errors v0.0.0-20191028224458-7d6c0bdb57a3
	github.com/sirupsen/logrus v1.4.2
	github.com/spf13/afero v1.2.2 // indirect
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/spf13/viper v1.4.0
	golang.org/x/crypto v0.0.0-20191029031824-8986dd9e96cf // indirect
	golang.org/x/net v0.0.0-20191028085509-fe3aa8a45271 // indirect
	golang.org/x/sys v0.0.0-20191029155521-f43be2a4598c // indirect
	gopkg.in/square/go-jose.v2 v2.4.0 // indirect
)

// rollbar-go: feature/pkgerrors-support
//replace github.com/rollbar/rollbar-go => ../rollbar-go

// rollbar-go: feature/pkgerrors-support
//replace github.com/rollbar/rollbar-go/errors => ../rollbar-go/errors

// rollrus: feature/use-official-rollbar
//replace github.com/heroku/rollrus => ../rollrus
