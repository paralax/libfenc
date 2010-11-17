#!/bin/bash
# For iPhoneOS.platform

export PATH=$PATH:/Developer/Platforms/iPhoneOS.platform/Developer/usr/bin:/Developer/usr/bin:/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS3.2.sdk

PREFIX="iOS-build"
ARM_GMP="-I/$PREFIX/include"
GCC_LIBS="-L/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS3.2.sdk/usr/lib/gcc/arm-apple-darwin9/4.2.1/v6"

./configure CC="/Developer/Platforms/iPhoneOS.platform/Developer/usr/bin/gcc-4.2" \
	CPP="/Developer/Platforms/iPhoneOS.platform/Developer/usr/bin/gcc-4.2 -E" \
	LD="/Developer/Platforms/iPhoneOS.platform/Developer/usr/bin/ld" \
	CPPFLAGS="-arch armv6 -isysroot /Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS3.2.sdk -miphoneos-version-min=3.0 $ARM_GMP" \
	LDFLAGS="$GCC_LIBS -L/$PREFIX/lib -march=armv6" --with-gnu-ld --disable-shared --enable-static --enable-optimized --prefix=/$PREFIX/ --host=arm-apple-darwin9

make

sudo make install

exit 0
