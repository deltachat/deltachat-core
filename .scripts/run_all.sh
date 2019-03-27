#!/bin/bash
#
# Build the Delta Chat C/Rust library
#
set -e -x

# clean-build and install core
export CORE_BUILD_DIR=/.docker-corebuild
[ -d "$CORE_BUILD_DIR" ] && rm -rf "$CORE_BUILD_DIR"

meson -Drpgp=true "$CORE_BUILD_DIR" .
    
pushd $CORE_BUILD_DIR 
ninja
ninja install
ldconfig -v
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

    pushd python
    pip install tox 
    tox 
    popd
fi


