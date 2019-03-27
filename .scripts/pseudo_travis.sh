#!/bin/bash
# perform what travis would do 
set -e -x

MYDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

export TRAVIS_BUILD_DIR=`realpath $MYDIR`

bash "$TRAVIS_BUILD_DIR/.scripts/travisbuild.sh"
