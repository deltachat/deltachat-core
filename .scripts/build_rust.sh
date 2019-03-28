
set -e -x 

# Install Rust 
curl https://sh.rustup.rs -sSf | sh -s -- --default-toolchain nightly-2019-03-23 -y
export PATH=/root/.cargo/bin:$PATH
rustc --version

# remove some 300-400 MB that we don't need for automated builds
rm -rf /root/.rustup/toolchains/nightly-2019-03-23-x86_64-unknown-linux-gnu/share/
