mkdir blst-sources && cd blst-sources
git clone https://github.com/supranational/blst
cd blst
git reset --hard $BLST_REF
./build.sh
cd ../..
