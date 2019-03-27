#!/bin/bash
#
# Build the Delta Chat C/Rust library
#
set -e -x

REPODIR=`dirname "$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"`

# build and install core
cd $REPODIR
meson -Drpgp=true builddir /mnt
pushd builddir
ninja
ninja install
ldconfig -v
popd

# run tests

if [ -n "$TESTS" ]; then 
    bash $REPODIR/.scripts/run_tests.sh
fi





