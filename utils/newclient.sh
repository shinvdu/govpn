#!/bin/sh -e

PATH=$PATH:.

[ -n "$1" ] || {
    cat <<EOF
Example script for creating new user peer for GoVPN.
It asks for passphrase, generates verifier and shows you example
JSON entry for server configuration.

Usage: $0 <username>
EOF
    exit 1
}

username=$1
umask 077
passphrase=$(mktemp)
$(dirname $0)/storekey.sh $passphrase
verifier=$(govpn-verifier -key $passphrase)
rm -f $passphrase
verifierS=$(echo $verifier | sed 's/^\(.*\) .*$/\1/')
verifierC=$(echo $verifier | sed 's/^.* \(.*\)$/\1/')
echo

cat <<EOF
Your client verifier is: $verifierC

Place the following JSON configuration entry on the server's side:

    "$username": {
        "up": "/path/to/up.sh",
        "iface": "or TAP interface name",
        "verifier": "$verifierS"
    }

Verifier was generated with:

    $(dirname $0)/storekey.sh /tmp/passphrase
    govpn-verifier -key /tmp/passphrase

Create up.sh script that will output on the first line TAP interface
name that must be used for the peer. For example:

    % umask 077
    % ed /path/to/up.sh
    a
    #!/bin/sh
    echo tap0
    .
    wq
    20
    % chmod +x /path/to/up.sh
EOF
