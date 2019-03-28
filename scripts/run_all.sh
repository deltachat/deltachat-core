#!/bin/bash
#
# Build the Delta Chat C/Rust library
#
set -e -x

# perform clean build of core and install 
export NINJA_BUILD_DIR=.docker-corebuild
export TOXWORKDIR=.docker-tox
[ -d "$NINJA_BUILD_DIR" ] && rm -rf "$NINJA_BUILD_DIR"

meson -Drpgp=true "$NINJA_BUILD_DIR" .
    
pushd $NINJA_BUILD_DIR 
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
    tox --workdir "$TOXWORKDIR" -e py27,py35,py36,py37

    # then possibly upload wheels 
    if [ -n "$WHEELS" ] ; then 
        # remove all wheels 
        rm -rf wheelhouse
        
        echo -----------------------
        echo build wheels 
        echo -----------------------

        for PYBIN in $TOXWORKDIR/py??/bin ; do 
            "${PYBIN}/pip" wheel . -w wheelhouse/
        done
        # Bundle external shared libraries into the wheels
        for whl in wheelhouse/deltachat*.whl; do
            auditwheel repair "$whl" -w wheelhouse
        done

        echo -----------------------
        echo upload wheels 
        echo -----------------------

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
    echo generating python docs
    echo -----------------------
    (cd python && tox --workdir "$TOXWORKDIR" -e doc) 

    # try to set ssh identity for upload from env var (set e.g. via CircleCI) 
    if [ ! -f ~/.ssh/delta_rsa ] ; then 
        if [ -n "${DELTA_UPLOAD_SSH_KEY}" ] ; then 
            mkdir -p ~/.ssh
            echo "${DELTA_UPLOAD_SSH_KEY}" > ~/.ssh/delta_rsa
            chmod 0700 ~/.ssh/delta_rsa
        fi
    fi

    # if we have an upload key, do the upload
    if [ -f ~/.ssh/delta_rsa ] ; then 
        # sync branch docs to py.delta.chat
        rsync -avz \
          -e "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null" \
          python/doc/_build/html/ \
          delta@py.delta.chat:build/${BRANCH}

        # Perform the actual deploy to c.delta.chat
        rsync -avz \
          -e "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null" \
          docs/html/ \
          delta@py.delta.chat:build-c/${BRANCH}
    fi
        
fi
