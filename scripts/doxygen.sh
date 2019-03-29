#!/bin/bash

set -xe


if [ -n "$DOCS" ] ; then 
    (cd docs && doxygen)
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
