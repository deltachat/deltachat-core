#!/bin/bash

set -xe

export WORKSPACE=${1:-.}
[ -d "$WORKSPACE" ] || echo "workspace dir '$WORKSPACE' does not exist" && exit 1

export BRANCH=${CIRCLE_BRANCH:?specify branch for uploading purposes}

if [ -z "$DEVPI_LOGIN" ] ; then 
    echo "required: password for 'dc' user on https://m.devpi/net/dc index"
    exit 1
fi

export WHEELHOUSE="$WORKSPACE/python/.docker-tox/wheelhouse"

[ -d "$WHEELHOUSE" ] || exit 1




# python docs to py.delta.chat
rsync -avz \
  -e "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null" \
  $WORKSPACE/python/doc/_build/html/ \
  delta@py.delta.chat:build/${BRANCH}

# C docs to c.delta.chat
rsync -avz \
  -e "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null" \
  $WORKSPACE/docs/html/ \
  delta@py.delta.chat:build-c/${BRANCH}

echo -----------------------
echo upload wheels 
echo -----------------------

# Bundle external shared libraries into the wheels
cd $WHEELHOUSE

for whl in deltachat*.whl; do
    auditwheel repair "$whl" -w wheelhouse
done

devpi use https://m.devpi.net
devpi login dc --password $DEVPI_LOGIN

devpi use dc/$BRANCH || {
    devpi index -c $BRANCH 
    devpi use dc/$BRANCH
}
devpi index $BRANCH bases=/root/pypi
devpi upload deltachat*.whl

