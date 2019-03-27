#!/bin/bash
#
# create docker image
#
: ${DOCKERIMAGE:?"required, names docker image in X/Y format"}

MYDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

docker build -t $DOCKERIMAGE $MYDIR
