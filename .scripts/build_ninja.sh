
set -e -x

NINJA_VERSION=v1.8.2
NINJA_SHA256=d2fea9ff33b3ef353161ed906f260d565ca55b8ca0568fa07b1d2cab90a84a07

curl -L -o ninja-linux-$NINJA_VERSION.zip \
     https://github.com/ninja-build/ninja/releases/download/${NINJA_VERSION}/ninja-linux.zip  

echo "${NINJA_SHA256}  ninja-linux-${NINJA_VERSION}.zip" | sha256sum -c -  
unzip ninja-linux-${NINJA_VERSION}.zip 
mv ninja /usr/bin/ninja 
/opt/python/cp37-cp37m/bin/pip install meson 

cd /usr/bin && ln -s /opt/_internal/cpython-3.7.*/bin/meson


