FROM quay.io/pypa/manylinux1_x86_64

# Configure ld.so/ldconfig and pkg-config
RUN echo /usr/local/lib64 > /etc/ld.so.conf.d/local.conf && \
    echo /usr/local/lib >> /etc/ld.so.conf.d/local.conf
ENV PKG_CONFIG_PATH /usr/local/lib64/pkgconfig:/usr/local/lib/pkgconfig

ENV PIP_DISABLE_PIP_VERSION_CHECK 1

# Install ninja
ADD build_ninja.sh /scripts/build_ninja.sh
RUN mkdir tmp1 && cd tmp1 && bash /scripts/build_ninja.sh && cd .. && rm -r tmp1

# Install a recent zlib, needed by libetpan
ADD build_zlib.sh /scripts/build_zlib.sh
RUN mkdir tmp1 && cd tmp1 && bash /scripts/build_zlib.sh && cd .. && rm -r tmp1

# Install a recent Perl, needed to install OpenSSL
ADD build_perl.sh /scripts/build_perl.sh
RUN mkdir tmp1 && cd tmp1 && bash /scripts/build_perl.sh && cd .. && rm -r tmp1

# Install OpenSSL
ADD build_openssl.sh /scripts/build_openssl.sh
RUN mkdir tmp1 && cd tmp1 && bash /scripts/build_openssl.sh && cd .. && rm -r tmp1

# Install cyrus-sasl
ADD build_sasl.sh /scripts/build_sasl.sh
RUN mkdir tmp1 && cd tmp1 && bash /scripts/build_sasl.sh && cd .. && rm -r tmp1

# Install libetpan
ADD build_libetpan.sh /scripts/build_libetpan.sh
RUN mkdir tmp1 && cd tmp1 && bash /scripts/build_libetpan.sh && cd .. && rm -r tmp1

# Install python tools (meson, tox, ...)
ADD build_python.sh /scripts/build_python.sh
RUN mkdir tmp1 && cd tmp1 && bash /scripts/build_python.sh && cd .. && rm -r tmp1

# Install Rust nightly 
ADD build_rust.sh /scripts/build_rust.sh
RUN mkdir tmp1 && cd tmp1 && bash /scripts/build_rust.sh && cd .. && rm -r tmp1

# Install RPGP from current github (beware, this is static in the image) 
# XXX: this needs to be installed Install 
ADD build_rpgp.sh /scripts/build_rpgp.sh
RUN mkdir tmp1 && cd tmp1 && bash /scripts/build_rpgp.sh && cd .. && rm -r tmp1
