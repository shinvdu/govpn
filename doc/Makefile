all: govpn.info govpn.html

MAKEINFO ?= makeinfo

handshake.utxt: handshake.txt
	plantuml -tutxt handshake.txt

govpn.info: *.texi handshake.utxt
	$(MAKEINFO) govpn.texi

govpn.html: *.texi handshake.utxt
	rm -f govpn.html/*.html
	$(MAKEINFO) --html --css-include=style.css -o govpn.html govpn.texi
