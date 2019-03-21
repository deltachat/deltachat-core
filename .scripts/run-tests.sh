#!/bin/bash

set -e
set -u
set -x
set -v

cd $TRAVIS_BUILD_DIR/python

openssl aes-256-cbc -K $encrypted_8a7f7373f4a3_key -iv $encrypted_8a7f7373f4a3_iv -in liveconfig-travis.enc -out liveconfig-travis -d

tox -- --liveconfig liveconfig-travis tests
