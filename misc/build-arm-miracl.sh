# Flatten out the filesystem for Unix/Linux use.
mkdir miracl2/
mv miracl2.zip miracl2/
cd miracl2/
unzip -j -aa -L miracl2.zip

echo "rm *.exe
rm *.lib
rm miracl.a
cp mirdef.arm mirdef.h
/Developer/Platforms/iPhoneOS.platform/Developer/usr/bin/gcc-4.2 -std=gnu99 -arch armv6 -isysroot /Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS3.0.sdk  -I. -c -02 mrcore.c
/Developer/Platforms/iPhoneOS.platform/Developer/usr/bin/gcc-4.2 -std=gnu99 -arch armv6 -isysroot /Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS3.0.sdk  -I. -c -02 mrarth0.c
/Developer/Platforms/iPhoneOS.platform/Developer/usr/bin/gcc-4.2 -std=gnu99 -arch armv6 -isysroot /Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS3.0.sdk  -I. -c -02 mrarth1.c
/Developer/Platforms/iPhoneOS.platform/Developer/usr/bin/gcc-4.2 -std=gnu99 -arch armv6 -isysroot /Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS3.0.sdk  -I. -c -02 mrarth2.c
/Developer/Platforms/iPhoneOS.platform/Developer/usr/bin/gcc-4.2 -std=gnu99 -arch armv6 -isysroot /Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS3.0.sdk  -I. -c -02 mralloc.c
/Developer/Platforms/iPhoneOS.platform/Developer/usr/bin/gcc-4.2 -std=gnu99 -arch armv6 -isysroot /Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS3.0.sdk  -I. -c -02 mrsmall.c
/Developer/Platforms/iPhoneOS.platform/Developer/usr/bin/gcc-4.2 -std=gnu99 -arch armv6 -isysroot /Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS3.0.sdk  -I. -c -02 mrio1.c
/Developer/Platforms/iPhoneOS.platform/Developer/usr/bin/gcc-4.2 -std=gnu99 -arch armv6 -isysroot /Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS3.0.sdk  -I. -c -02 mrio2.c
/Developer/Platforms/iPhoneOS.platform/Developer/usr/bin/gcc-4.2 -std=gnu99 -arch armv6 -isysroot /Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS3.0.sdk  -I. -c -02 mrgcd.c
/Developer/Platforms/iPhoneOS.platform/Developer/usr/bin/gcc-4.2 -std=gnu99 -arch armv6 -isysroot /Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS3.0.sdk  -I. -c -02 mrjack.c
/Developer/Platforms/iPhoneOS.platform/Developer/usr/bin/gcc-4.2 -std=gnu99 -arch armv6 -isysroot /Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS3.0.sdk  -I. -c -02 mrbits.c
/Developer/Platforms/iPhoneOS.platform/Developer/usr/bin/gcc-4.2 -std=gnu99 -arch armv6 -isysroot /Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS3.0.sdk  -I. -c -02 mrxgcd.c
/Developer/Platforms/iPhoneOS.platform/Developer/usr/bin/gcc-4.2 -std=gnu99 -arch armv6 -isysroot /Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS3.0.sdk  -I. -c -02 mrarth3.c
/Developer/Platforms/iPhoneOS.platform/Developer/usr/bin/gcc-4.2 -std=gnu99 -arch armv6 -isysroot /Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS3.0.sdk  -I. -c -02 mrrand.c
/Developer/Platforms/iPhoneOS.platform/Developer/usr/bin/gcc-4.2 -std=gnu99 -arch armv6 -isysroot /Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS3.0.sdk  -I. -c -02 mrprime.c
/Developer/Platforms/iPhoneOS.platform/Developer/usr/bin/gcc-4.2 -std=gnu99 -arch armv6 -isysroot /Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS3.0.sdk  -I. -c -02 mrcrt.c
/Developer/Platforms/iPhoneOS.platform/Developer/usr/bin/gcc-4.2 -std=gnu99 -arch armv6 -isysroot /Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS3.0.sdk  -I. -c -02 mrscrt.c
/Developer/Platforms/iPhoneOS.platform/Developer/usr/bin/gcc-4.2 -std=gnu99 -arch armv6 -isysroot /Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS3.0.sdk  -I. -c -02 mrmonty.c
/Developer/Platforms/iPhoneOS.platform/Developer/usr/bin/gcc-4.2 -std=gnu99 -arch armv6 -isysroot /Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS3.0.sdk  -I. -c -02 mrpower.c
/Developer/Platforms/iPhoneOS.platform/Developer/usr/bin/gcc-4.2 -std=gnu99 -arch armv6 -isysroot /Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS3.0.sdk  -I. -c -02 mrsroot.c
/Developer/Platforms/iPhoneOS.platform/Developer/usr/bin/gcc-4.2 -std=gnu99 -arch armv6 -isysroot /Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS3.0.sdk  -I. -c -02 mrcurve.c
/Developer/Platforms/iPhoneOS.platform/Developer/usr/bin/gcc-4.2 -std=gnu99 -arch armv6 -isysroot /Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS3.0.sdk  -I. -c -02 mrfast.c
/Developer/Platforms/iPhoneOS.platform/Developer/usr/bin/gcc-4.2 -std=gnu99 -arch armv6 -isysroot /Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS3.0.sdk  -I. -c -02 mrshs.c
/Developer/Platforms/iPhoneOS.platform/Developer/usr/bin/gcc-4.2 -std=gnu99 -arch armv6 -isysroot /Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS3.0.sdk  -I. -c -02 mrshs256.c
/Developer/Platforms/iPhoneOS.platform/Developer/usr/bin/gcc-4.2 -std=gnu99 -arch armv6 -isysroot /Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS3.0.sdk  -I. -c -02 mrshs512.c
/Developer/Platforms/iPhoneOS.platform/Developer/usr/bin/gcc-4.2 -std=gnu99 -arch armv6 -isysroot /Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS3.0.sdk  -I. -c -02 mraes.c
/Developer/Platforms/iPhoneOS.platform/Developer/usr/bin/gcc-4.2 -std=gnu99 -arch armv6 -isysroot /Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS3.0.sdk  -I. -c -02 mrlucas.c
/Developer/Platforms/iPhoneOS.platform/Developer/usr/bin/gcc-4.2 -std=gnu99 -arch armv6 -isysroot /Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS3.0.sdk  -I. -c -02 mrstrong.c
/Developer/Platforms/iPhoneOS.platform/Developer/usr/bin/gcc-4.2 -std=gnu99 -arch armv6 -isysroot /Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS3.0.sdk  -I. -c -02 mrbrick.c
/Developer/Platforms/iPhoneOS.platform/Developer/usr/bin/gcc-4.2 -std=gnu99 -arch armv6 -isysroot /Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS3.0.sdk  -I. -c -02 mrebrick.c
/Developer/Platforms/iPhoneOS.platform/Developer/usr/bin/gcc-4.2 -std=gnu99 -arch armv6 -isysroot /Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS3.0.sdk  -I. -c -02 mrgf2m.c
/Developer/Platforms/iPhoneOS.platform/Developer/usr/bin/gcc-4.2 -std=gnu99 -arch armv6 -isysroot /Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS3.0.sdk  -I. -c -02 mrec2m.c
/Developer/Platforms/iPhoneOS.platform/Developer/usr/bin/gcc-4.2 -std=gnu99 -arch armv6 -isysroot /Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS3.0.sdk  -I. -c -02 mrzzn2.c
/Developer/Platforms/iPhoneOS.platform/Developer/usr/bin/gcc-4.2 -std=gnu99 -arch armv6 -isysroot /Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS3.0.sdk  -I. -c -02 mrzzn2b.c
/Developer/Platforms/iPhoneOS.platform/Developer/usr/bin/gcc-4.2 -std=gnu99 -arch armv6 -isysroot /Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS3.0.sdk  -I. -c -02 mrzzn3.c
/Developer/Platforms/iPhoneOS.platform/Developer/usr/bin/gcc-4.2 -std=gnu99 -arch armv6 -isysroot /Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS3.0.sdk  -I. -c -02 mrecn2.c
ar -rc miracl.a mrcore.o mrarth0.o mrarth1.o mrarth2.o mralloc.o mrsmall.o
ar -r  miracl.a mrio1.o mrio2.o mrjack.o mrgcd.o mrxgcd.o mrarth3.o
ar -r  miracl.a mrrand.o mrprime.o mrcrt.o mrscrt.o mrmonty.o mrcurve.o 
ar -r  miracl.a mrfast.o mrshs.o mraes.o mrlucas.o mrstrong.o mrbrick.o 
ar -r  miracl.a mrebrick.o mrec2m.o mrgf2m.o mrpower.o mrsroot.o mrzzn2b.o
ar -r  miracl.a mrshs256.o mrshs512.o mrbits.o mrzzn2.o mrzzn3.o mrecn2.o
rm mr*.o
/Developer/Platforms/iPhoneOS.platform/Developer/usr/bin/g++-4.2 -arch armv6 -isysroot /Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS3.0.sdk  -02 ibe_set.cpp zzn2.cpp big.cpp zzn.cpp ecn.cpp miracl.a -o ibe_setup
/Developer/Platforms/iPhoneOS.platform/Developer/usr/bin/g++-4.2 -arch armv6 -isysroot /Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS3.0.sdk  -02 ibe_ext.cpp big.cpp zzn.cpp ecn.cpp miracl.a -o ibe_ext
/Developer/Platforms/iPhoneOS.platform/Developer/usr/bin/g++-4.2 -arch armv6 -isysroot /Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS3.0.sdk  -02 ibe_enc.cpp zzn2.cpp big.cpp zzn.cpp ecn.cpp miracl.a -o ibe_enc
/Developer/Platforms/iPhoneOS.platform/Developer/usr/bin/g++-4.2 -arch armv6 -isysroot /Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS3.0.sdk  -02 ibe_dec.cpp zzn2.cpp big.cpp zzn.cpp ecn.cpp miracl.a -o ibe_dec" > build-arm

bash build-arm

cp miracl.a /iPhoneOS-build/lib/miracl.a
mkdir /iPhoneOS-build/include/miracl/
cp *.h /iPhoneOS-build/include/miracl/

echo "Compiled IBE example for iPhoneOS."
