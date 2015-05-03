.PHONY: govpn-client govpn-server govpn-verifier

LDFLAGS=-X govpn.Version $(shell cat VERSION)

all: govpn-client govpn-server govpn-verifier

dependencies:
	[ "$(shell uname)" = FreeBSD ] || go get github.com/bigeagle/water
	go get golang.org/x/crypto/poly1305
	go get golang.org/x/crypto/salsa20
	go get golang.org/x/crypto/xtea
	go get golang.org/x/crypto/pbkdf2
	go get github.com/agl/ed25519

govpn-client: dependencies
	go build -ldflags "$(LDFLAGS)" govpn/cmd/govpn-client

govpn-server: dependencies
	go build -ldflags "$(LDFLAGS)" govpn/cmd/govpn-server

govpn-verifier: dependencies
	go build -ldflags "$(LDFLAGS)" govpn/cmd/govpn-verifier

bench: dependencies
	GOMAXPROC=2 go test -bench .
