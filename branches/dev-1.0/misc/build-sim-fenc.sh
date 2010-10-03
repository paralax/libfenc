#!/bin/bash

# For iPhoneSimulator.platform
# Note: gmp and pbc for me were installed in /iPhoneSimulator-build/ 
# May need to adjust references in header files for this script to work in  your environment.

export PATH=$PATH:/Developer/Platforms/iPhoneSimulator.platform/Developer/usr/bin:/Developer/usr/bin:/Developer/Platforms/iPhoneSimulator.platform/Developer/SDKs/iPhoneOS3.1.3.sdk

CC="/Developer/Platforms/iPhoneSimulator.platform/Developer/usr/bin/gcc-4.2" 
CPP="/Developer/Platforms/iPhoneSimulator.platform/Developer/usr/bin/gcc-4.2 -E" 
CPPFLAGS="-arch i386 -isysroot /Developer/Platforms/iPhoneSimulator.platform/Developer/SDKs/iPhoneSimulator3.0.sdk -miphoneos-version-min=3.0" 
PREFIX="/iPhoneSimulator-build"
CCFLAGS="-fnested-functions -Wall -W -Wfloat-equal -Wpointer-arith -Wcast-align -Wredundant-decls -Wendif-labels -Wshadow -pipe -ffast-math -U__STRICT_ANSI__ -L$PREFIX/lib -g -I$PREFIX/include"

make CC=$CC CCFLAGS="$CPPFLAGS $CCFLAGS" SLIBS="$PREFIX/lib/libgmp.a $PREFIX/lib/libpbc.a ./libfenc.a"
