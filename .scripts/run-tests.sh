#!/bin/bash

set -e
set -u
set -x
set -v

NAME=liveconfig-travis3

cd $TRAVIS_BUILD_DIR/python

openssl aes-256-cbc -K $encrypted_fd8d0295d62e_key -iv $encrypted_fd8d0295d62e_iv -in $NAME.enc -out $NAME  -d

tox -e py35,lint -- --maxfail=3 --liveconfig $NAME tests
