#!/bin/sh -e

getrand()
{
    local size=$1
    dd if=/dev/urandom bs=$size count=1 2>/dev/null | hexdump -ve '"%02x"'
}

[ -n "$1" ] || {
    cat <<EOF
Example script for creating new user peer for GoVPN.
It just creates directory with random peer ID, dummy verifier,
dummy up.sh executable script and saves username in it.

Usage: $0 <username>
EOF
    exit 1
}

username=$1
peerid=$(getrand 16)
umask 077
mkdir -p peers/$peerid
echo '0000000000000000000000000000000000000000000000000000000000000000' > peers/$peerid/verifier
echo $username > peers/$peerid/name
echo '#!/bin/sh' > peers/$peerid/up.sh
chmod 700 peers/$peerid/up.sh
echo Place verifier to peers/$peerid/verifier
