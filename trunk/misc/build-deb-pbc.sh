#!/bin/bash

echo "You will need to install debhelper, libreadline-dev, and dpkg-dev build .deb"

# You can probably comment out the below, but this is the only order I have
# tested on thus far.
./configure
make

# The following is from the original makedep.sh.
set -e

if [ ! -f pbc/parser.tab.c -o pbc/parser.y -nt pbc/parser.tab.c ]; then
    bison -d -b pbc/parser pbc/parser.y
fi

if [ ! -f pbc/lex.yy.c -o pbc/parser.lex -nt pbc/lex.yy.c ]; then
    flex -o pbc/lex.yy.c --header-file=pbc/lex.yy.h pbc/parser.lex
fi

dpkg-buildpackage -d -rfakeroot

echo "To install, dpkg -i ../libpbc0*, followed by dpkg -i ../libpbc-dev*."

# If you would like to remove the packages later:
#    sudo dpkg -r libpbc-dev
#    sudo dpkg -r libpbc0
