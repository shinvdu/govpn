#!/bin/sh -ex

cur=$(pwd)
tmp=$(mktemp -d)
release=$1
[ -n "$release" ]

git clone . $tmp/govpn-$release
for repo in src/github.com/bigeagle/water src/github.com/agl/ed25519 src/golang.org/x/crypto; do
    git clone $repo $tmp/govpn-$release/$repo
done
cd $tmp/govpn-$release
git checkout $release
git submodule update --init

cat > $tmp/includes <<EOF
golang.org/x/crypto/AUTHORS
golang.org/x/crypto/CONTRIBUTORS
golang.org/x/crypto/LICENSE
golang.org/x/crypto/PATENTS
golang.org/x/crypto/README
golang.org/x/crypto/curve25519
golang.org/x/crypto/pbkdf2
golang.org/x/crypto/poly1305
golang.org/x/crypto/salsa20
golang.org/x/crypto/xtea
EOF
tar cfCI - src $tmp/includes | tar xfC - $tmp
rm -fr src/golang.org
mv $tmp/golang.org src/
rm -fr $tmp/golang.org $tmp/includes

cat > doc/download.texi <<EOF
@node Prepared tarballs
@section Prepared tarballs
You can obtain releases source code prepared tarballs on
@url{http://www.cypherpunks.ru/govpn/}.
EOF
make -C doc

rm utils/makedist.sh
find . -name .git -type d | xargs rm -fr
find . -name .gitignore -delete

cd ..
tar cvf govpn-"$release".tar govpn-"$release"
xz -9 govpn-"$release".tar
gpg --detach-sign --sign --local-user F2F59045FFE2F4A1 govpn-"$release".tar.xz
mv $tmp/govpn-"$release".tar.xz $tmp/govpn-"$release".tar.xz.sig $cur/doc/govpn.html/download
