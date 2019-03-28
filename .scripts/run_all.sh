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
ln -s /opt/python/cp37-cp37m/bin/python3.7
popd

#
# run ninja and python tests
#

if [ -n "$TESTS" ]; then 
    echo ----------------
    echo run ninja tests
    echo ----------------

    # ninja test

    echo ----------------
    echo run python tests
    echo ----------------

    pushd python 
    # first run all tests ...
    tox -e py27,py35,py36,py37

    # then possibly upload wheels 
    if [ -n "$WHEELS" ] ; then 
        # remove all wheels 
        rm -rf wheelhouse

        # Build wheels 
        for PYBIN in .tox/py??/bin ; do 
            "${PYBIN}/pip" wheel . -w wheelhouse/
        done
        # Bundle external shared libraries into the wheels
        for whl in wheelhouse/deltachat*.whl; do
            auditwheel repair "$whl" -w wheelhouse
        done
        # upload wheels 
        devpi use https://m.devpi.net
        devpi login dc --password $DEVPI_LOGIN

        devpi use dc/$BRANCH || {
            devpi index -c $BRANCH 
            devpi use dc/$BRANCH
        }
        devpi index $BRANCH bases=/root/pypi
        devpi upload wheelhouse/deltachat*.whl
    fi

    popd
fi


if [ -n "$DOCS" ]; then 
    echo -----------------------
    echo generating doxygen docs
    echo -----------------------

    (cd docs && doxygen)

    (cd python && tox -e doc) 
fi
