#!/bin/bash
#
# Build the Delta Chat C/Rust library
#
set -e -x

# perform clean build of core and install 
export CORE_BUILD_DIR=.docker-corebuild
[ -d "$CORE_BUILD_DIR" ] && rm -rf "$CORE_BUILD_DIR"

meson -Drpgp=true "$CORE_BUILD_DIR" .
    
pushd $CORE_BUILD_DIR 
ninja
ninja install
ldconfig -v
popd


# configure access to a base python and 
# to several python interpreters needed by tox below
export PATH=$PATH:/opt/python/cp35-cp35m/bin
export PYTHONDONTWRITEBYTECODE=1
pushd /bin
ln -s /opt/python/cp27-cp27m/bin/python2.7
ln -s /opt/python/cp36-cp36m/bin/python3.6
ln -s /opt/python/cp36-cp37m/bin/python3.7
popd

# run ninja and python tests

if [ -n "$TESTS" ]; then 
    echo ----------------
    echo run ninja tests
    echo ----------------

    # ninja test

    echo ----------------
    echo run python tests
    echo ----------------

    (cd python && tox -e py27,py35,py36)
fi


if [ -n "$DOCS" ]; then 
    echo -----------------------
    echo generating doxygen docs
    echo -----------------------

    (cd docs && doxygen)

    (cd python && tox -e doc) 
fi
