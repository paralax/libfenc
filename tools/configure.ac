# -*- Autoconf -*-
dnl  Process this file with autoconf to produce a configure script.

define(TOOLS_COPYRIGHT,[[

FENC Tools Copyright is blank for now.  Licensing information coming soon.

]])
AC_COPYRIGHT(TOOLS_COPYRIGHT)
AH_TOP(/*TOOLS_COPYRIGHT*/)


AC_PREREQ([2.65])
AC_INIT([tools], [0.2], [mgreen at cs dot jhu dot edu])
AC_CONFIG_SRCDIR([mgabe-enc.c])
AC_CONFIG_HEADERS([config.h])

# Prepairing for the automake.
AM_INIT_AUTOMAKE

# Set the default directory to /usr/.  Let's keep it @ /usr/local
#AC_PREFIX_DEFAULT([/usr/])

# Checks for programs; shouldn't need to check for all of these, 
# but will leave intact.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET

# If macosx, than check for macports or fink default installation.
default_macports_path=/opt/local
default_fink_path=/sw
case $host_os in
     darwin*) 
              # Perhaps this will be useful some time.
     	      #dnl nested function support
     	      #AC_MSG_NOTICE([Adding -fnested-functions to CFLAGS])
	      #CFLAGS="-fnested-functions"

	      dnl fink or macports installation
     	      AC_MSG_CHECKING([for a fink or macports installation at $default_fink_path and $default_macports_path])
     	      if test -d $default_fink_path; then 
	      	 AC_MSG_RESULT([found fink!])
		 AC_MSG_NOTICE([Adding -I$default_fink_path/include to CPPFLAGS])
	      	 CPPFLAGS="-I$default_fink_path/include $CPPFLAGS"
		 AC_MSG_NOTICE([Adding -L$default_fink_path/lib to LDFLAGS])
		 LDFLAGS="-L$default_fink_path/lib $LDFLAGS"
              elif test -d $default_macports_path; then
		 AC_MSG_RESULT([found macports!])
		 AC_MSG_NOTICE([Adding -I$default_macports_path/include to CPPFLAGS])
	      	 CPPFLAGS="-I$default_macports_path/include $CPPFLAGS"
		 AC_MSG_NOTICE([Adding -L$default_macports_path/lib to LDFLAGS])
		 LDFLAGS="-L$default_macports_path/lib $LDFLAGS"
	      else
		AC_MSG_RESULT(none)
		AC_MSG_NOTICE([You may need to add set CPPFLAGS and LDFLAGS for gmp, etc.])
	      fi
	      ;;
esac

# AC_CHECK_LIB([crypto], [main])
# Checks for libraries.
lib_err_msg="add its path to LDFLAGS\nsee ./configure --help"
AC_CHECK_LIB( [m], [pow], [],[
	      echo "************************"
	      echo "m library not found"
	      echo -e $lib_err_msg
	      echo "************************"
	      exit -1
	      ])
AC_CHECK_LIB( [gmp], [__gmpz_init], [],[
	      echo "************************"
	      echo "gmp library not found"
	      echo -e $lib_err_msg
	      echo "************************"
	      exit -1
	      ])
AC_CHECK_LIB( [fenc], [libfenc_init], [],[
	      echo "************************"
	      echo "libfenc library not found"
              echo "   Linux?  Have you tried sudo"
              echo "   ldconfig to update your"
              echo "   ld.so.cache?"
	      echo -e $lib_err_msg
	      echo "************************"
	      exit -1
	      ])
AC_CHECK_LIB( [crypto], [DES_xcbc_encrypt], [],[
	      echo "************************"
	      echo "OpenSSL library not found"
	      echo -e $lib_err_msg
	      echo "************************"
	      exit -1
	      ])
AC_CHECK_LIB( [pbc], [pbc_set_msg_to_stderr], [],[
	      echo "************************"
	      echo "pbc library not found"
              echo "   Linux?  Have you tried sudo"
              echo "   ldconfig to update your"
              echo "   ld.so.cache?"
	      echo -e $lib_err_msg
	      echo "************************"
	      exit -1
	      ])

dnl setup CFLAGS
with_enable_optimized="no"
AC_ARG_ENABLE( optimized, 
	       [AC_HELP_STRING([--enable-optimized],
			[Enable optimized build])],
         [with_enable_optimized="$withval"],
	 [with_enable_optimized="no"])

CFLAGS="$CFLAGS -W -Wfloat-equal -Wpointer-arith -Wcast-align -Wredundant-decls -Wendif-labels \
-Wshadow -pipe -ffast-math -U__STRICT_ANSI__"

if test "x$with_enable_optimized" != "no"; then
   	CFLAGS="$CFLAGS -g"
else
	CFLAGS="$CFLAGS -fomit-frame-pointer -O3"
fi

# Checks for header files.
AC_CHECK_HEADERS([stdlib.h string.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset pow strchr strdup])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

# Print configuration to the user.
echo -ne "\n"
echo "global build variables"
echo "-----------------------------------------"
echo `date`
echo "host info:        $host"
echo "optimized build:  $with_enable_optimized"
echo "LDFLAGS:          $LDFLAGS"
echo "CPPFLAGS:         $CPPFLAGS"
echo "CFLAGS:           $CFLAGS"
echo "-----------------------------------------"
echo -ne "\n"
