#!/bin/sh -e

[ -n "$1" ] || {
    cat <<EOF
Example script for creating new user peer for GoVPN.
It generates random client's identity, ask for passphrase, generates
verifier and shows you example JSON entry for server configuration.

Usage: $0 <username>
EOF
    exit 1
}

username=$1
peerid=$(dd if=/dev/urandom bs=16 count=1 2>/dev/null | hexdump -ve '"%02x"')
[ $(echo -n $peerid | wc -c) = 32 ] || peerid=0"$peerid"
umask 077
passphrase=$(mktemp)
$(dirname $0)/storekey.sh $passphrase
verifier=$(govpn-verifier -id $peerid -key $passphrase)
rm -f $passphrase
echo

cat <<EOF
Your id is: $peerid

Place the following JSON configuration entry on the server's side:

    "$peerid": {
        "name": "$username",
        "up": "/path/to/up.sh",
        "verifier": "$verifier"
    }

Verifier was generated with:

    $(dirname $0)/storekey.sh /tmp/passphrase
    govpn-verifier -id $peerid -key /tmp/passphrase

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
