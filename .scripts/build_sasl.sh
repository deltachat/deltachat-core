
set -e -x

SASL_VERSION=2.1.27
SASL_SHA256=26866b1549b00ffd020f188a43c258017fa1c382b3ddadd8201536f72efb05d5

curl -O https://www.cyrusimap.org/releases/cyrus-sasl-${SASL_VERSION}.tar.gz
echo "${SASL_SHA256}  cyrus-sasl-${SASL_VERSION}.tar.gz" | sha256sum -c -
tar zxf cyrus-sasl-${SASL_VERSION}.tar.gz

cd cyrus-sasl-${SASL_VERSION} 

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

make
make install 
ldconfig -v |grep -i sasl 
