#!/bin/bash
#sudo touch /etc/ld.so.conf.d/libfenc.conf
#sudo sh -c "echo '/usr/local/lib' > /etc/ld.so.conf.d/libfenc.conf"


# This was tested on Ubuntu 10.04 LTS.  To get this working for another
# distro of linux, try uncommenting the following:

#sudo echo "# libfenc default configuration
#/usr/local/lib" >> /etc/ld.so.conf

# Now to update, and check for our libs.
sudo ldconfig
ldconfig -p | grep libfenc*

