#!/bin/sh -e

[ -n "$1" ] || {
    cat <<EOF
Read passphrase from stdin and store it in file.

Usage: $0 <keyfilename>
EOF
    exit 1
}

echo -n Enter passphrase:
stty -echo
read passphrase
stty echo
umask 077
cat > $1 <<EOF
$passphrase
EOF
