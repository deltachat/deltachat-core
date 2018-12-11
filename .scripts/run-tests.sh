#!/bin/bash

set -e
set -u
set -x
set -v

cd $TRAVIS_BUILD_DIR/python

openssl aes-256-cbc -K $encrypted_fd8d0295d62e_key -iv $encrypted_fd8d0295d62e_iv -in travis-liveconfig.enc -out travis-liveconfig -d

tox -- --liveconfig travis-liveconfig 

