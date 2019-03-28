#!/bin/bash
# perform what travis would do 
set -e -x

export TRAVIS_BUILD_DIR=$PWD

cd $TRAVIS_BUILD_DIR

bash scripts/travisbuild.sh
