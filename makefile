.PHONY: govpn-client govpn-server govpn-verifier

GOPATH=$(shell pwd)
export GOPATH

LDFLAGS=-X govpn.Version $(shell cat VERSION)

all: govpn-client govpn-server govpn-verifier

depends:
	$(MAKE) -C src

govpn-client: depends
	go build -ldflags "$(LDFLAGS)" govpn/cmd/govpn-client

govpn-server: depends
	go build -ldflags "$(LDFLAGS)" govpn/cmd/govpn-server

govpn-verifier: depends
	go build -ldflags "$(LDFLAGS)" govpn/cmd/govpn-verifier

bench:
	cd src/govpn ; GOMAXPROC=2 go test -bench .
