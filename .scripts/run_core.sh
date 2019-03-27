#!/bin/bash
#
# Build the Delta Chat C/Rust library
#
set -e -x

meson -Drpgp=true /builddir /mnt
pushd /builddir
ninja
ninja install
ldconfig -v
popd
