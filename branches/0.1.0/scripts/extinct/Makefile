
CC = gcc
CCFLAGS = -fnested-functions -Wall -W -Wfloat-equal -Wpointer-arith -Wcast-align -Wredundant-decls -Wendif-labels -Wshadow -pipe -ffast-math -U__STRICT_ANSI__ -L/usr/local/lib -g -m64 -arch x86_64 -I../ -I../../pbc-0.5.6/include
CCLIBS = -lstdc++
AR = ar
ARARGS = rcs

PBCLIBS = ../../pbc-0.5.6/.libs/libpbc.dylib /usr/local/lib/libgmp.dylib
LIBRARY = ../libfenc.a
LIBRARYOBJ = libfenc.o libfenc_LSW.o libfenc_ABE_common.o libfenc_LSSS.o libfenc_group_params.o libfenc_utils.o sha1.o
LIBRARYSRC = libfenc.c libfenc_LSW.c libfenc_ABE_common.c libfenc_LSSS.o libfenc_group_params.c libfenc_utils.c sha1.h
LIBRARYH = libfenc.h libfenc_LSW.h libfenc_ABE_common.h libfenc_LSSS.h libfenc_group_params.h libfenc_utils.h sha1.h

all: abedemo

abedemo: abedemo.c
	${CC} -o abedemo ${CCFLAGS} -L. -L.. -lfenc abedemo.c ${PBCLIBS}
	
clean:
	rm -rf *.o a.out abedemo 

%.o: %.c
	${CC} ${CCFLAGS} -c $<

%.o: %.cpp
	${CC} ${CCFLAGS} -c $<

%.h:
