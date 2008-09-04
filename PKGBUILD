# Package build script for Arch Linux,
# contributed by Alexander Drozdov.

pkgname=pdnsd
pkgver=1.2.7
pkgrel=1
pkgdesc="pdnsd is a proxy DNS server with permanent caching (the cache contents are written to hard disk on exit) that is designed to cope with unreachable or down DNS servers."
url="http://www.phys.uu.nl/~rombouts/pdnsd.html"
license="GPLv3"
depends=()
makedepends=(glibc)
conflicts=()
replaces=()
backup=()
install=
source=(http://www.phys.uu.nl/~rombouts/pdnsd/releases/$pkgname-$pkgver-par.tar.gz)
md5sums=()

build() {
  cd $startdir/src/$pkgname-$pkgver
  ./configure --prefix=/usr --enable-ipv6 --sysconfdir=/etc --with-distribution=ArchLinux
  make || return 1
  make DESTDIR=$startdir/pkg install
}
