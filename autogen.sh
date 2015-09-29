#! /bin/sh

cd ./libs/zlog-master
./autogen.sh
cd ../../

# if [ ! -d ./m4 ]; then mkdir ./m4; fi
# aclocal
# autoheader
# automake --add-missing
# autoconf

libtoolize -fc

autoreconf --install --force

