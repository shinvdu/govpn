all: govpn.info govpn.html

MAKEINFO ?= makeinfo

govpn.info: *.texi handshake.utxt
	$(MAKEINFO) govpn.texi

handshake.utxt: handshake.txt
	plantuml -tutxt handshake.txt

govpn.html: *.texi handshake.utxt
	rm -f govpn.html/*.html
	$(MAKEINFO) --html -o govpn.html govpn.texi
