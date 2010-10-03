#!/bin/bash

# For iPhoneSimulator.platform

export PATH=$PATH:/Developer/Platforms/iPhoneSimulator.platform/Developer/usr/bin:/Developer/usr/bin:/Developer/Platforms/iPhoneSimulator.platform/Developer/SDKs/iPhoneSimulator3.1.3.sdk

ARM_GMP="-I/iPhoneSimulator-build/include"
GCC_LIBS="-L/Developer/Platforms/iPhoneSimulator.platform/Developer/SDKs/iPhoneSimulator3.0.sdk/usr/lib/gcc/arm-apple-darwin9/4.2.1/v6"

./configure CC="/Developer/Platforms/iPhoneSimulator.platform/Developer/usr/bin/gcc-4.2" CPP="/Developer/Platforms/iPhoneSimulator.platform/Developer/usr/bin/gcc-4.2 -E" LD="/Developer/Platforms/iPhoneSimulator.platform/Developer/usr/bin/ld" CPPFLAGS="-arch i386 -isysroot /Developer/Platforms/iPhoneSimulator.platform/Developer/SDKs/iPhoneSimulator3.0.sdk -miphoneos-version-min=3.0 $ARM_GMP" LDFLAGS="-L/iPhoneSimulator-build/lib -march=i386" --enable-static --prefix=/iPhoneSimulator-build/ 

make

# installs shared library and header files into /iPhoneSimulator-build/
sudo make install
