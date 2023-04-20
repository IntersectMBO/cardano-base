#!/bin/bash
# I don't understand why this just vanishes.
export PATH=/usr/bin:$PATH

mkdir blst-sources && cd blst-sources
git clone https://github.com/supranational/blst
cd blst
git reset --hard $BLST_REF
./build.sh

mkdir -p pkgconfig
cat <<EOF > pkgconfig/libblst.pc
prefix=$PWD
exec_prefix=\${prefix}
libdir=$PWD
includedir=\${prefix}/bindings

Name: libblst
Version: 0.3.10
Description: Multilingual BLS12-381 signature library

Cflags: -I\${includedir}
Libs: -L\${libdir} -lblst
EOF

cd ../..
