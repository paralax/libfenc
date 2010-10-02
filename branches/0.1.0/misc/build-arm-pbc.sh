#!/bin/bash
# For iPhoneOS.platform

export PATH=$PATH:/Developer/Platforms/iPhoneOS.platform/Developer/usr/bin:/Developer/usr/bin:/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS3.1.3.sdk

SDK_CC="/Developer/Platforms/iPhoneOS.platform/Developer/usr/bin/gcc-4.2 -arch armv6"
SDK_HDRS="/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS3.1.3.sdk/usr/lib/gcc/arm-apple-darwin9"

ARM_GMP="-I/iPhoneOS-build/include"
GCC_LIBS="-L/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS3.1.3.sdk/usr/lib/gcc/arm-apple-darwin9/4.2.1/v6"

./configure CC="/Developer/Platforms/iPhoneOS.platform/Developer/usr/bin/gcc-4.2" CPP="/Developer/Platforms/iPhoneOS.platform/Developer/usr/bin/gcc-4.2 -E" LD="/Developer/Platforms/iPhoneOS.platform/Developer/usr/bin/ld" CPPFLAGS="-arch armv6 -isysroot /Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS3.1.3.sdk -miphoneos-version-min=3.0 $ARM_GMP" LDFLAGS="$GCC_LIBS -L/iPhoneOS-build/lib -march=armv6" --with-gnu-ld --disable-shared --enable-static --enable-optimized --prefix=/iPhoneOS-build/ --host=arm-apple-darwin9

make

sudo cp -rf include /iPhoneOS-build/include/pbc/

cd ./.libs
sudo cp libpbc.{a,la} /iPhoneOS-build/lib

cd -
