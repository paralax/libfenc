# JAA note: redo the Makefile: includes, libraries

CC = gcc
CCFLAGS = -Wall -W -Wfloat-equal -Wpointer-arith -Wcast-align -Wredundant-decls -Wendif-labels -Wshadow -pipe -ffast-math -U__STRICT_ANSI__ -L/usr/local/lib -g -I/usr/local/include
#CCFLAGS = -fnested-functions -Wall -W -Wfloat-equal -Wpointer-arith -Wcast-align -Wredundant-decls -Wendif-labels -Wshadow -pipe -ffast-math -U__STRICT_ANSI__ -L/usr/local/lib -g -m64 -arch x86_64 -I../pbc-0.5.6/include
CCLIBS = -lstdc++
AR = ar
ARARGS = rcs
MAKE = make
BISON = bison
PREFIX = /usr/local

PBCLIBS = ../pbc-0.5.6/.libs/libpbc.dylib /usr/local/lib/libgmp.dylib
LIBRARY = libfenc
TARGET_LIB = libfenc.a libfenc.so
LIBRARYOBJ = libfenc.o libfenc_LSW.o libfenc_WatersCP.o libfenc_ABE_common.o libfenc_LSSS.o libfenc_group_params.o libfenc_utils.o sha1.o policy_lang.tab.o
LIBRARYSRC = libfenc.c libfenc_LSW.c libfenc_WatersCP.c libfenc_ABE_common.c libfenc_LSSS.o libfenc_group_params.c libfenc_utils.c sha1.c policy_lang.tab.c
LIBRARYH = libfenc.h libfenc_LSW.h libfenc_WatersCP.h libfenc_ABE_common.h libfenc_LSSS.h libfenc_group_params.h libfenc_utils.h sha1.h

all: libfenc test_libfenc abedemo test_libfencCP

libfenc: ${LIBRARYOBJ} ${LIBRARYH}
	 # static
	 ${AR} ${ARARGS} ${LIBRARY}.a ${LIBRARYOBJ}
	 # dynamic (linux)
	 #$(CC) -shared -W1,-soname -o ${LIBRARY}.so ${LIBRARYOBJ}

test_libfenc: libfenc test_libfenc.c
	${CC} -o test_libfenc ${CCFLAGS} -L. -lfenc test_libfenc.c ${PBCLIBS}

test_libfencCP: libfenc test_libfencCP.c
	${CC} -o test_libfencCP ${CCFLAGS} -L. -lfenc test_libfencCP.c ${PBCLIBS}
	
abedemo: libfenc
	(cd abedemo; ${MAKE})

install:
	install -m 755 ${TARGET_LIB} ${PREFIX}/lib

clean:
	rm -rf *.o a.out test_libfenc ${TARGET_LIB}
	(cd abedemo; ${MAKE} clean)

%.o: %.c
	${CC} ${CCFLAGS} -c $<

%.o: %.cpp
	${CC} ${CCFLAGS} -c $<

%.tab.c: %.y
	${BISON} $<

%.h:
