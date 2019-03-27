

set -e -x

ETPAN_VERSION=1.9.1
ETPAN_SHA256=f5e354ccf1014c6ee313ade1009b8a82f28043d2504655e388bb4c1328700fcd
curl -L -o libetpan-${ETPAN_VERSION}.tar.gz \
    https://github.com/dinhviethoa/libetpan/archive/${ETPAN_VERSION}.tar.gz
echo "${ETPAN_SHA256}  libetpan-${ETPAN_VERSION}.tar.gz" | sha256sum -c -
tar xzf libetpan-${ETPAN_VERSION}.tar.gz
cd libetpan-${ETPAN_VERSION} 
./autogen.sh && \
./configure --enable-ipv6 \
            --enable-iconv --disable-db \
            --with-openssl --with-sasl --with-zlib \
            --without-curl --without-expat
make
make install
ldconfig -v | grep -i etpan 
