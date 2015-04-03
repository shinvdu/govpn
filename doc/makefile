all: govpn.info govpn.html

govpn.info: *.texi handshake.utxt
	makeinfo govpn.texi

handshake.utxt: handshake.txt
	plantuml -tutxt handshake.txt

govpn.html: *.texi handshake.utxt
	rm -f govpn.html/*.html
	makeinfo --html -o govpn.html govpn.texi
