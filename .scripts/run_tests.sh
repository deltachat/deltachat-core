#!/bin/bash
#
# Run Ninja and Python tests against the installed core lib
#
set -e -x

: ${REPODIR:?"required, points to repository checkout root directory"}

echo ----------------
echo run ninja tests
echo ----------------

cd $REPODIR/builddir
ninja test

echo ----------------
echo run python tests
echo ----------------

cd $REPODIR/python
virtualenv venv
source venv/bin/activate
pip install tox 
tox 
