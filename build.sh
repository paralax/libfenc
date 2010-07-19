#!/bin/bash
# (Temporary script)
# Description: this script will build all the libfenc shared object and prototype tools that use the library.
# Author: Joseph Ayo Akinyele

cmd=$1

if [ $# -eq 0 ]; then
   echo "$0: [ option ]"
   echo "\toptions: help, all, src, tools, bench"
   exit 1
fi

if [ $cmd == "all" ]; then
   echo "Building src and tools..."
   $(cd src; ./configure CC="gcc -arch i386" CXX="g++ -arch i386")
   make -C src/
   $(cd tools; ./configure CC="gcc -arch i386" CXX="g++ -arch i386")
   make -C tools/
elif [ $cmd == "src" ]; then
   echo "Building src..." 
   $(cd src; ./configure CC="gcc -arch i386" CXX="g++ -arch i386")
   make -C src/
elif [ $cmd == "tools" ]; then
   echo "Building tools..." 
   $(cd tools; ./configure CC="gcc -arch i386" CXX="g++ -arch i386")
   make -C tools/
elif [ $cmd == "bench" ]; then
   echo "Building library optimized..."
   make -C src/ clean
   $(cd src; ./configure CC="gcc -arch i386" CXX="g++ -arch i386" --enable-optimized)
   make -C src/
   make -C benchmarks/
elif [ $cmd == "docs" ]; then
   echo "Building documentation..."
elif [ $cmd == "clean" ]; then
   make -C src/ clean
   make -C tools/ clean
else
   echo "$0: [ option ]"
   echo "\toptions: help, all, src, tools, docs"
fi

exit 0
