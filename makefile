.PHONY: govpn-client govpn-server

LDFLAGS=-X govpn.Version $(shell cat VERSION)

all: govpn-client govpn-server

dependencies:
	[ "$(shell uname)" = FreeBSD ] || go get github.com/bigeagle/water
	go get golang.org/x/crypto/poly1305
	go get golang.org/x/crypto/salsa20
	go get golang.org/x/crypto/xtea

govpn-client: dependencies
	go build -ldflags "$(LDFLAGS)" govpn/cmd/govpn-client

govpn-server: dependencies
	go build -ldflags "$(LDFLAGS)" govpn/cmd/govpn-server

bench: dependencies
	GOMAXPROC=2 go test -bench .
