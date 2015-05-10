GOPATH != pwd
VERSION != cat VERSION

LDFLAGS=-X govpn.Version $(VERSION)

all: govpn-client govpn-server govpn-verifier

depends:
	$(MAKE) -C src

govpn-client: depends
	GOPATH=$(GOPATH) go build -ldflags "$(LDFLAGS)" govpn/cmd/govpn-client

govpn-server: depends
	GOPATH=$(GOPATH) go build -ldflags "$(LDFLAGS)" govpn/cmd/govpn-server

govpn-verifier: depends
	GOPATH=$(GOPATH) go build -ldflags "$(LDFLAGS)" govpn/cmd/govpn-verifier

bench:
	cd src/govpn ; GOPATH=$(GOPATH) GOMAXPROC=2 go test -bench .
