#!/bin/bash

# For iPhoneSimulator.platform

export PATH=$PATH:/Developer/Platforms/iPhoneSimulator.platform/Developer/usr/bin:/Developer/usr/bin:/Developer/Platforms/iPhoneSimulator.platform/Developer/SDKs/iPhoneOS3.1.3.sdk

./configure CC="/Developer/Platforms/iPhoneSimulator.platform/Developer/usr/bin/gcc-4.2" CPP="/Developer/Platforms/iPhoneSimulator.platform/Developer/usr/bin/gcc-4.2 -E" LD="/Developer/Platforms/iPhoneSimulator.platform/Developer/usr/bin/ld" CPPFLAGS="-arch i386 -isysroot /Developer/Platforms/iPhoneSimulator.platform/Developer/SDKs/iPhoneSimulator3.0.sdk -miphoneos-version-min=3.0 -DNO_ASM" --enable-static --prefix=/iPhoneSimulator-build/ --host=none-apple-darwin9

make

sudo make install
