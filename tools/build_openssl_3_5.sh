#!/usr/bin/env bash

set -e
set -x

build_dir=/var/tmp/newtools_build
rm -rf ${build_dir}
mkdir -p ${build_dir}
cd ${build_dir}

# Build openssl:
OPENSSL_VERSION=3.5.0
somewhere1=/opt/openssl
git clone --quiet --depth=1 -b openssl-$OPENSSL_VERSION https://github.com/openssl/openssl
cd openssl
./config --prefix=${somewhere1} --libdir=lib
while ! make -j`nproc` install_sw; do echo "trying openssl build again"; done
chmod -R a+rX /opt

# Build nghttp3:
NGHTTP3_VERSION=v1.9.0
cd ..
git clone -b $NGHTTP3_VERSION https://github.com/ngtcp2/nghttp3
cd nghttp3
git submodule update --init
autoreconf -fi
./configure --prefix=/opt --enable-lib-only
make -j`nproc`
make install
chmod -R a+rX /opt

# Build ngtcp2:
NGTCP2_VERSION=v1.12.0
cd ..
git clone -b $NGTCP2_VERSION https://github.com/ngtcp2/ngtcp2
cd ngtcp2
autoreconf -fi
./configure PKG_CONFIG_PATH=${somewhere1}/lib/pkgconfig:/opt/lib/pkgconfig LDFLAGS="-Wl,-rpath,${somewhere1}/lib" --prefix=/opt --enable-lib-only --with-openssl
make -j`nproc`
make install
chmod -R a+rX /opt

# Build curl:
cd ..
git clone https://github.com/curl/curl
cd curl
autoreconf -fi
LDFLAGS="-Wl,-rpath,${somewhere1}/lib" ./configure --prefix=/opt --with-openssl=${somewhere1} --with-nghttp3=/opt --with-ngtcp2=/opt
make -j`nproc`
make install
chmod -R a+rX /opt
