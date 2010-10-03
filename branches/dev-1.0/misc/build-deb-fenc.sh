#!/bin/bash

echo "You will need to install debhelper, libreadline-dev, and dpkg-dev build .deb"

./configure
make

dpkg-buildpackage -d -rfakeroot

echo "To install, dpkg -i ../libfenc_0*, followed by dpkg -i ../libfenc-dev*."

# If you would like to remove the packages later:
#    sudo dpkg -r libfenc-dev
#    sudo dpkg -r libfenc_0*
