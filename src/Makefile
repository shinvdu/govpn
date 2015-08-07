GIT ?= git

all: golang.org/x/crypto github.com/agl/ed25519 github.com/bigeagle/water

github.com/bigeagle/water:
	mkdir -p github.com/bigeagle
	$(GIT) clone https://github.com/bigeagle/water.git github.com/bigeagle/water
	cd github.com/bigeagle/water && $(GIT) checkout --force 36aebfeb35da4f1f6a975726716c6fc563c5c495

github.com/agl/ed25519:
	mkdir -p github.com/agl
	$(GIT) clone https://github.com/agl/ed25519.git github.com/agl/ed25519
	cd github.com/agl/ed25519 && $(GIT) checkout --force d2b94fd789ea21d12fac1a4443dd3a3f79cda72c

golang.org/x/crypto:
	mkdir -p golang.org/x
	$(GIT) clone https://go.googlesource.com/crypto golang.org/x/crypto
	cd golang.org/x/crypto && $(GIT) checkout --force 2f3083f6163ef51179ad42ed523a18c9a1141467
