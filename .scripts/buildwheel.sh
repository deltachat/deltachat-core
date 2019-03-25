#!/bin/bash

set -e -x

docker pull deltachat/wheel 
rm -rf python/wheelhouse/*
cd $TRAVIS_BUILD_DIR
docker run --rm -it -v $(pwd):/io deltachat/wheel /io/python/wheelbuilder/build-wheels.sh

# create an index at the community "devpi" python packaging site
# and push both binary wheel packages and the source package to
# the https://m.devpi.net/dc/BRANCHNAME index 
devpi use https://m.devpi.net
devpi login dc --password $DEVPI_LOGIN

devpi use dc/$BRANCH || {
    devpi index -c $BRANCH 
    devpi use dc/$BRANCH
}
devpi index $BRANCH bases=/root/pypi

devpi upload --from-dir python/wheelhouse

cd python
devpi upload 
