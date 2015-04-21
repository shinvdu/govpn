#!/bin/sh -e

getrand()
{
    local size=$1
    dd if=/dev/random bs=$size count=1 2>/dev/null | hexdump -ve '"%02x"'
}

[ -n "$1" ] || {
    cat <<EOF
Example script for creating new user peer for GoVPN.
It just creates directory with random peer ID and random key in it,
and adds empty file with human readable username.

Usage: $0 <username>
EOF
    exit 1
}

username=$1
peerid=$(getrand 16)
umask 077
mkdir -p peers/$peerid
getrand 32 > peers/$peerid/key
touch peers/$peerid/$1
echo peers/$peerid/$1
