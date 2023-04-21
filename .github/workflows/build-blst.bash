#!/bin/bash
# I don't understand why this just vanishes.
export PATH=/usr/bin:$PATH

mkdir blst-sources && cd blst-sources
git clone https://github.com/supranational/blst
cd blst
git reset --hard $BLST_REF
./build.sh

sudo mkdir -p ${PREFIX}/lib/pkgconfig
sudo mkdir -p ${PREFIX}/include/blst
cp bindings/{blst.h,blst_aux.h} ${PREFIX}/include/blst/ 
cp -f libblst.{a,dll,so,dylib} ${PREFIX}/lib/

sudo cat <<EOF > ${PREFIX}/lib/pkgconfig/libblst.pc
prefix=${PREFIX}
exec_prefix=\${prefix}
libdir=\${prefix}
includedir=\${prefix}/include/blst

Name: libblst
Version: 0.3.10
Description: Multilingual BLS12-381 signature library

Cflags: -I\${includedir}
Libs: -L\${libdir} -lblst
EOF

cd ../..
