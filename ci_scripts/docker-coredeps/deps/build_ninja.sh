
set -e -x

NINJA_VERSION=v1.8.2
NINJA_SHA256=d2fea9ff33b3ef353161ed906f260d565ca55b8ca0568fa07b1d2cab90a84a07

curl -L -o ninja-linux-$NINJA_VERSION.zip \
     https://github.com/ninja-build/ninja/releases/download/${NINJA_VERSION}/ninja-linux.zip  

echo "${NINJA_SHA256}  ninja-linux-${NINJA_VERSION}.zip" | sha256sum -c -  
unzip ninja-linux-${NINJA_VERSION}.zip 
mv ninja /usr/bin/ninja 

