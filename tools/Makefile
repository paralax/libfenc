# Note: Change prefix. configure script coming!
PREFIX = /iPhoneSimulator-build
INSTALLDIR = ${PREFIX}/bin

# derived from above parameters
INCLUDES = -I${PREFIX}/include -I../src
CCFLAGS = -W -Wfloat-equal -Wpointer-arith -Wcast-align -Wredundant-decls -Wendif-labels -Wshadow -pipe -ffast-math -U__STRICT_ANSI__ -g -O2 ${INCLUDES}
LIBDIR = ${PREFIX}/lib
LIBS = ${LIBDIR}/libgmp.a ${LIBDIR}/libpbc.a ${LIBDIR}/libfenc.a
SSL = $(LIBDIR)/libcrypto.a
TARGETS = abe-setup abe-keygen abe-enc abe-dec

all: $(TARGETS)

abe-setup: mgabe-setup.o base64.o
	$(CC) $(CCFLAGS) -o $@ $^ $(LIBS)	

abe-keygen: mgabe-keygen.o base64.o
	$(CC) $(CCFLAGS) -o $@ $^ $(LIBS)

abe-enc: mgabe-enc.o base64.o
	$(CC) $(CCFLAGS) -o $@ $^ $(LIBS) $(SSL)

abe-dec: mgabe-dec.o base64.o
	$(CC) $(CCFLAGS) -o $@ $^ $(LIBS) $(SSL)

install:
	mkdir -p $(INSTALLDIR)
	install -m 755 $(TARGETS) $(INSTALLDIR)
clean:
	rm -rf $(TARGETS) *.o

%.o: %.c
	$(CC) $(CCFLAGS) -c $<


