
set -e -x 

# Install RPGP from github 
export PATH=$PATH:$HOME/.cargo/bin
git clone --depth 1 https://github.com/dignifiedquire/rpgp.git 
cd rpgp/pgp-ffi 
make install 

# after we installed the RPGP lib we don't need Rust anymore
# rm -rf /root/.cargo /root.rustup
