FROM quay.io/pypa/manylinux1_x86_64

# Configure ld.so/ldconfig and pkg-config
RUN echo /usr/local/lib64 > /etc/ld.so.conf.d/local.conf && \
    echo /usr/local/lib >> /etc/ld.so.conf.d/local.conf
ENV PKG_CONFIG_PATH /usr/local/lib64/pkgconfig:/usr/local/lib/pkgconfig

# Install meson and ninja
ENV NINJA_VERSION v1.8.2
RUN /opt/python/cp37-cp37m/bin/pip install meson
RUN cd /usr/bin && ln -s /opt/_internal/cpython-3.7.0/bin/meson
RUN curl -L -O https://github.com/ninja-build/ninja/releases/download/${NINJA_VERSION}/ninja-linux.zip
RUN unzip ninja-linux.zip && mv ninja /usr/bin/ninja

# Install a recent zlib, needed by libetpan
ENV ZLIB_VERSION 1.2.11
RUN curl -O https://www.zlib.net/zlib-${ZLIB_VERSION}.tar.gz
RUN tar xzf zlib-${ZLIB_VERSION}.tar.gz
RUN cd zlib-${ZLIB_VERSION} && ./configure
RUN cd zlib-${ZLIB_VERSION} && make
RUN cd zlib-${ZLIB_VERSION} && make install
RUN ldconfig -v

# Install a recent Perl, needed to install OpenSSL
ENV PERL_VERSION 5.28.0
RUN curl -O https://www.cpan.org/src/5.0/perl-${PERL_VERSION}.tar.gz
RUN tar xzf perl-${PERL_VERSION}.tar.gz
RUN cd perl-${PERL_VERSION} && ./Configure -de
RUN cd perl-${PERL_VERSION} && make
RUN cd perl-${PERL_VERSION} && make install

# Install OpenSSL
ENV OPENSSL_VERSION 1.1.1a
RUN curl -O https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz
RUN tar xzf openssl-${OPENSSL_VERSION}.tar.gz
RUN cd openssl-${OPENSSL_VERSION} && \
    ./config shared no-ssl2 no-ssl3 -fPIC --prefix=/usr/local
RUN cd openssl-${OPENSSL_VERSION} && \
    sed -i "s/^SHLIB_MAJOR=.*/SHLIB_MAJOR=200/" Makefile && \
    sed -i "s/^SHLIB_MINOR=.*/SHLIB_MINOR=0.0/" Makefile && \
    sed -i "s/^SHLIB_VERSION_NUMBER=.*/SHLIB_VERSION_NUMBER=200.0.0/" Makefile
RUN cd openssl-${OPENSSL_VERSION} && make depend
RUN cd openssl-${OPENSSL_VERSION} && make
RUN cd openssl-${OPENSSL_VERSION} && make install_sw install_ssldirs

RUN ldconfig -v

# Install cyrus-sasl
ENV SASL_VERSION 2.1.27
RUN curl -O ftp://ftp.cyrusimap.org/cyrus-sasl/cyrus-sasl-${SASL_VERSION}.tar.gz
RUN tar zxf cyrus-sasl-${SASL_VERSION}.tar.gz
RUN cd cyrus-sasl-${SASL_VERSION} && \
    ./configure --disable-silent-rules \
                --disable-cmulocal \
                --disable-sample \
                --disable-obsolete_cram_attr \
                --disable-obsolete_digest_attr \
                --disable-staticdlopen \
                --disable-java \
                --disable-alwaystrue \
                --enable-checkapop \
                --enable-cram \
                --enable-digest \
                --enable-scram \
                --disable-otp \
                --disable-srp \
                --disable-srp-setpass \
                --disable-krb4 \
                --disable-gssapi \
                --disable-gss_mutexes \
                --disable-sia \
                --disable-auth-sasldb \
                --disable-httpform \
                --enable-plain \
                --enable-anon \
                --enable-login \
                --disable-ntlm \
                --disable-passdss \
                --disable-sql \
                --disable-ldapdb \
                --disable-macos-framework
RUN cd cyrus-sasl-${SASL_VERSION} && make
RUN cd cyrus-sasl-${SASL_VERSION} && make install
RUN ldconfig -v

# Install libetpan
ENV ETPAN_VERSION 1.9.1
RUN curl -L -o libetpan-${ETPAN_VERSION}.tar.gz \
    https://github.com/dinhviethoa/libetpan/archive/${ETPAN_VERSION}.tar.gz
RUN tar xzf libetpan-${ETPAN_VERSION}.tar.gz
RUN cd libetpan-${ETPAN_VERSION} && ./autogen.sh && \
    ./configure --enable-ipv6 \
                --disable-iconv --disable-db \
                --with-openssl --with-sasl --with-zlib \
                --without-curl --without-expat
RUN cd libetpan-${ETPAN_VERSION} && make
RUN cd libetpan-${ETPAN_VERSION} && make install
RUN ldconfig -v
