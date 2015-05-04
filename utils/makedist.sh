#!/bin/sh -ex

cur=$(pwd)
tmp=$(mktemp -d)
release=$1
[ -n "$release" ]
git clone . $tmp/govpn-$release
cd $tmp/govpn-$release
git checkout $release
rm -fr .git
find . -name .gitignore -delete
cat > doc/download.texi <<EOF
@node Prepared tarballs
@section Prepared tarballs
You can obtain releases source code prepared tarballs on
@url{http://www.cypherpunks.ru/govpn/}.
EOF
rm utils/makedist.sh
make -C doc
cd $tmp
tar cvf govpn-"$release".tar govpn-"$release"
xz -9 govpn-"$release".tar
gpg --detach-sign --sign --local-user FFE2F4A1 govpn-"$release".tar.xz
mv $tmp/govpn-"$release".tar.xz $tmp/govpn-"$release".tar.xz.sig $cur/doc/govpn.html/download
