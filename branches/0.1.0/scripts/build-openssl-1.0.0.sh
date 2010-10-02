#!/bin/bash

# Shell script to get openssl up and ready for the iphone.
# Tweaked shell script from the following source:
#    http://github.com/shigeyas/build-openssl-iphone/blob/master/BUILD-OpenSSL.sh
#
# Modification to include the use of the latest openssl source, configured --no-asm
# option to successfully build, and minor changes to DISTDIR / directory cleaning.
# 
# May 22nd, 2010.

############################################################

TARGET=openssl-1.0.0
SDK_VERSION=3.0

############################################################


build_openssl() {

# First argument provided; used to set the distdir.
LIBNAME=$1
case $LIBNAME in
device) DISTDIR="/iPhoneOS-build/";;
*) DISTDIR="/iPhoneSimulator-build/";;
esac
#DISTDIR=`pwd`/iPhoneSimulator-build/-$LIBNAME

# Second argument provided.
PLATFORM=$2

echo "Building binary for iPhone $LIBNAME $PLATFORM to $DISTDIR"


# Match word to our first input of device, iPhoneOS, or * for the simulator.
case $LIBNAME in
device) ARCH="armv6";;
*) ARCH="i386";;
esac

# Original script installed to /bin/.  This one does not, please run the script
# inside of openSSL.


# This chunk will patch the ui_openssl.c file as explained on the following thread:
# http://www.therareair.com/2009/01/01/tutorial-how-to-compile-openssl-for-the-iphone/
echo "Patching crypto/ui/ui_openssl.c"
echo From: `fgrep 'intr_signal;' crypto/ui/ui_openssl.c`
perl -pi.bak \
    -e 's/static volatile sig_atomic_t intr_signal;/static volatile int intr_signal;/;' \
    crypto/ui/ui_openssl.c
echo To: `fgrep 'intr_signal;' crypto/ui/ui_openssl.c`


# Setup compile version for the device, much like the gmp shell script.
PATH=$PATH:/Developer/Platforms/${PLATFORM}.platform/Developer/usr/bin:/Developer/usr/bin
SDKPATH="/Developer/Platforms/${PLATFORM}.platform/Developer/SDKs/${PLATFORM}${SDK_VERSION}.sdk"

mkdir ${DISTDIR}

# --openssldir no-asm
./config no-asm --prefix=${DISTDIR}

perl -pi.bak \
    -e "s;CC= cc;CC = /Developer/Platforms/${PLATFORM}.platform/Developer/usr/bin/gcc-4.2; ;" \
    -e "s;CFLAG= ;CFLAG=-arch ${ARCH} -isysroot ${SDKPATH} ; ;" \
    -e "s;-arch i386;-arch ${ARCH}; ;" \
Makefile

# So the simulator will actually build.
case $LIBNAME in
simulator)
perl -pi.bak \
-e 'if (/LIBDEPS=/) { s/\)}";/\)} -L.";/; }' \
            Makefile.shared
(cd apps; ln -s ${SDKPATH}/usr/lib/crt1.10.5.o crt1.10.6.o);
(cd test; ln -s ${SDKPATH}/usr/lib/crt1.10.5.o crt1.10.6.o);
;;
esac


make
sudo make install

# Just a quick clean-up so we don't have overlap between the iPhoneSimulator and the iPhoneOS
mkdir ${PLATFORM}
sudo mv libcrypto.* ${PLATFORM}/
sudo mv libssl.* ${PLATFORM}/

}

build_openssl "device" "iPhoneOS"
build_openssl "simulator" "iPhoneSimulator"


# End of script.
