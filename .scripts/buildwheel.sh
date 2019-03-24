#!/bin/bash

set -e -x

docker pull deltachat/wheel 
rm -rf python/wheelhouse/*
cd $TRAVIS_BUILD_DIR
docker run --rm -it -v $(pwd):/io deltachat/wheel /io/python/wheelbuilder/build-wheels.sh

devpi use https://m.devpi.net
devpi login dc --password $DEVPI_LOGIN

devpi use dc/$TRAVIS_BRANCH || {
    devpi index -c $TRAVIS_BRANCH 
    devpi use dc/$TRAVIS_BRANCH
}

devpi upload --from-dir python/wheelhouse

cd python
devpi upload 
