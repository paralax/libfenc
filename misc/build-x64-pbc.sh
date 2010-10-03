#!/bin/bash

# To build PBC on MacOS Leopard, 64-bit:
#   * Get the latest version of gmp, make sure configure is using it
#   * Copy "gmp.h" into this directory and comment out the following line:
#
#     #define __GMP_EXTERN_INLINE extern __inline__ __attribute__ ((__gnu_inline__))
#
#     (NOTE: I've already done it in this directory.)

./configure CPPFLAGS="-m64" CFLAGS="-m64"
