#!/bin/sh -ex

[ -n "$SHA256" ] || SHA256=sha256

cur=$(pwd)
tmp=$(mktemp -d)
release=$1
[ -n "$release" ]

git clone . $tmp/govpn-$release
for repo in src/github.com/bigeagle/water src/github.com/agl/ed25519 src/github.com/magical/argon2 src/github.com/dchest/blake2b src/golang.org/x/crypto; do
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
@node Tarballs
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

tarball=$cur/doc/govpn.html/download/govpn-"$release".tar.xz
size=$(( $(cat $tarball | wc -c) / 1024 ))
hash=$($SHA256 $tarball | sed 's/^.*\([0-9a-f]\{64\}\).*$/\1/')
cat <<EOF
An entry for documentation:
@item $release @tab $size KiB
@tab @url{download/govpn-${release}.tar.xz, link} @url{download/govpn-${release}.tar.xz.sig, sign}
@tab @code{$hash}
EOF

cd $cur

cat <<EOF
Subject: [EN] GoVPN $release release announcement

I am pleased to announce GoVPN $release release availability!

GoVPN is simple free software virtual private network daemon, aimed to
be reviewable, secure, DPI/censorship-resistant, written on Go.

It uses fast strong passphrase authenticated key agreement protocol with
augmented zero-knowledge mutual peers authentication (PAKE DH A-EKE).
Encrypted, authenticated data transport that hides message's length and
timestamps. Perfect forward secrecy property. Resistance to: offline
dictionary attacks, replay attacks, client's passphrases compromising
and dictionary attacks on the server side. Built-in heartbeating,
rehandshaking, real-time statistics. Ability to work through UDP, TCP
and HTTP proxies. IPv4/IPv6-compatibility. GNU/Linux and FreeBSD support.

----------------8<-----------------8<-----------------8<----------------

The main improvements for that release are:

$(git cat-file -p $release | sed -n '6,/^.*BEGIN/p' | sed '$d')

----------------8<-----------------8<-----------------8<----------------

GoVPN's home page is: http://govpn.info -> http://www.cypherpunks.ru/govpn/
also available as Tor hidden service: http://vabu56j2ep2rwv3b.onion/govpn/

Source code and its signature for that version can be found here:

    http://www.cypherpunks.ru/govpn/download/govpn-${release}.tar.xz ($size KiB)
    http://www.cypherpunks.ru/govpn/download/govpn-${release}.tar.xz.sig

SHA256 hash: $hash
GPG key ID: 0xF2F59045FFE2F4A1 GoVPN release signing key
Fingerprint: D269 9B73 3C41 2068 D8DA  656E F2F5 9045 FFE2 F4A1

Please send questions regarding the use of GoVPN, bug reports and patches
to mailing list: https://lists.cypherpunks.ru/pipermail/govpn-devel/
EOF

cat <<EOF
Subject: [RU] Состоялся релиз GoVPN $release

Я рад сообщить о выходе релиза GoVPN $release!

GoVPN это простой демон виртуальных частных сетей, код которого нацелен
на лёгкость чтения и анализа, безопасность, устойчивость к DPI/цензуре,
написан на Go и является свободным программным обеспечением.

Он использует быстрый сильный аутентифицируемый по парольной фразе
несбалансированный протокол согласования ключей с двусторонней
аутентификацией сторон (PAKE DH A-EKE). Зашифрованный, аутентифицируемый
транспортный протокол передачи данных, скрывающий длины сообщений и их
временные характеристики. Свойство совершенной прямой секретности.
Устойчивость к: внесетевым (offline) атакам по словарю, атакам
повторного воспроизведения (replay), компрометации клиентских парольных
фраз на стороне сервера. Встроенные функции сердцебиения (heartbeat),
пересогласования ключей, статистика реального времени. Возможность
работы поверх UDP, TCP и HTTP прокси. Совместимость с IPv4 и IPv6.
Поддержка GNU/Linux и FreeBSD.

----------------8<-----------------8<-----------------8<----------------

Основные усовершенствования в этом релизе:

$(git cat-file -p $release | sed -n '6,/^.*BEGIN/p' | sed '$d')

----------------8<-----------------8<-----------------8<----------------

Домашняя страница GoVPN: http://govpn.info -> http://www.cypherpunks.ru/govpn/
Коротко о демоне: http://www.cypherpunks.ru/govpn/About-RU.html
также доступна как скрытый сервис Tor: http://vabu56j2ep2rwv3b.onion/govpn/

Исходный код и его подпись для этой версии находится здесь:

    http://www.cypherpunks.ru/govpn/download/govpn-${release}.tar.xz ($size KiB)
    http://www.cypherpunks.ru/govpn/download/govpn-${release}.tar.xz.sig

SHA256 хэш: $hash
Идентификатор GPG ключа: 0xF2F59045FFE2F4A1 GoVPN release signing key
Отпечаток: D269 9B73 3C41 2068 D8DA  656E F2F5 9045 FFE2 F4A1

Пожалуйста все вопросы касающиеся использования GoVPN, отчёты об ошибках
и патчи отправляйте в govpn-devel почтовую рассылку:
https://lists.cypherpunks.ru/pipermail/govpn-devel/
EOF
