#!/bin/bash

set -e -x 

# Install RPGP from github 
# XXX built a particular version like the other dep scripts do

export PATH=$PATH:$HOME/.cargo/bin
git clone https://github.com/rpgp/rpgp.git 
cd rpgp/pgp-ffi 
make install 

# after we installed the RPGP lib we don't need Rust anymore
# rm -rf /root/.cargo /root.rustup
