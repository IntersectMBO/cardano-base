#!/bin/bash
# I don't understand why this just vanishes.
export PATH=/usr/bin:$PATH

mkdir blst-sources && cd blst-sources
git clone https://github.com/supranational/blst
cd blst
git reset --hard $BLST_REF
./build.sh
echo $PWD
cd ../..
