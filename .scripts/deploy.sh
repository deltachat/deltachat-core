#!/bin/bash
set -e
set -u
set -x

#Only attempt to deploy if we know the ssh key secrets, username and server
if test -z ${encrypted_ee89c1e228aa_key:+decryp_key} ; then exit 0; fi
if test -z ${encrypted_ee89c1e228aa_iv:+decrypt_iv} ; then exit 0; fi
if test -z ${DEPLOY_USER:+username} ; then exit 0; fi
if test -z ${DEPLOY_SERVER:+server} ; then exit 0; fi

# Prepare the ssh homedir.
#
# Decrypting the ssh private key for deploying to the server.
# See https://docs.travis-ci.com/user/encrypting-files/ for details.
mkdir -p -m 0700 ~/.ssh
openssl aes-256-cbc -K $encrypted_ee89c1e228aa_key -iv $encrypted_ee89c1e228aa_iv -in .credentials/autocrypt.id_rsa.enc -out ~/.ssh/id_rsa -d
chmod 600 ~/.ssh/id_rsa
cat .credentials/autocrypt.org.hostkeys >> ~/.ssh/known_hosts
printf "Host *\n" >> ~/.ssh/config
printf " %sAuthentication no\n" ChallengeResponse Password KbdInteractive >> ~/.ssh/config


# Perform the actual deploy
rsync -avz $TRAVIS_BUILD_DIR/doc/_build/html/ \
  ${DEPLOY_USER}@${DEPLOY_SERVER}:build/${TRAVIS_BRANCH/\//_}
rsync -avz $TRAVIS_BUILD_DIR/doc/_build/latex/autocrypt*.pdf \
  ${DEPLOY_USER}@${DEPLOY_SERVER}:build/${TRAVIS_BRANCH/\//_}
