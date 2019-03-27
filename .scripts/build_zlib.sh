
set -e -x

ZLIB_VERSION=1.2.11
ZLIB_SHA256=c3e5e9fdd5004dcb542feda5ee4f0ff0744628baf8ed2dd5d66f8ca1197cb1a1

curl -O https://www.zlib.net/zlib-${ZLIB_VERSION}.tar.gz
echo "${ZLIB_SHA256}  zlib-${ZLIB_VERSION}.tar.gz" | sha256sum -c -
tar xzf zlib-${ZLIB_VERSION}.tar.gz
cd zlib-${ZLIB_VERSION} 
./configure
make
make install
ldconfig -v 
