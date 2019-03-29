FROM quay.io/pypa/manylinux1_x86_64

# Configure ld.so/ldconfig and pkg-config
RUN echo /usr/local/lib64 > /etc/ld.so.conf.d/local.conf && \
    echo /usr/local/lib >> /etc/ld.so.conf.d/local.conf
ENV PKG_CONFIG_PATH /usr/local/lib64/pkgconfig:/usr/local/lib/pkgconfig

ENV PIP_DISABLE_PIP_VERSION_CHECK 1

# Install ninja
ADD deps/build_ninja.sh /scripts/build_ninja.sh
RUN mkdir tmp1 && cd tmp1 && bash /scripts/build_ninja.sh && cd .. && rm -r tmp1

# Install a recent zlib, needed by libetpan
ADD deps/build_zlib.sh /builder/build_zlib.sh
RUN mkdir tmp1 && cd tmp1 && bash /builder/build_zlib.sh && cd .. && rm -r tmp1

# Install a recent Perl, needed to install OpenSSL
ADD deps/build_perl.sh /builder/build_perl.sh
RUN mkdir tmp1 && cd tmp1 && bash /builder/build_perl.sh && cd .. && rm -r tmp1

# Install OpenSSL
ADD deps/build_openssl.sh /builder/build_openssl.sh
RUN mkdir tmp1 && cd tmp1 && bash /builder/build_openssl.sh && cd .. && rm -r tmp1

# Install cyrus-sasl
ADD deps/build_sasl.sh /builder/build_sasl.sh
RUN mkdir tmp1 && cd tmp1 && bash /builder/build_sasl.sh && cd .. && rm -r tmp1

# Install libetpan
ADD deps/build_libetpan.sh /builder/build_libetpan.sh
RUN mkdir tmp1 && cd tmp1 && bash /builder/build_libetpan.sh && cd .. && rm -r tmp1

# Install python tools (meson, tox, ...)
ADD deps/build_python.sh /builder/build_python.sh
RUN mkdir tmp1 && cd tmp1 && bash /builder/build_python.sh && cd .. && rm -r tmp1

# Install Rust nightly 
ADD deps/build_rust.sh /builder/build_rust.sh
RUN mkdir tmp1 && cd tmp1 && bash /builder/build_rust.sh && cd .. && rm -r tmp1

# Install RPGP from current github (beware, will be static in the docker image) 
# XXX: this needs to be installed properly 
ADD deps/build_rpgp.sh /builder/build_rpgp.sh
RUN mkdir tmp1 && cd tmp1 && bash /builder/build_rpgp.sh && cd .. && rm -r tmp1
