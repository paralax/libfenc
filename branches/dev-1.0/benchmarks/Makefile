# Note: Change prefix. configure script coming!
PREFIX = /usr/local
INSTALLDIR = ${PREFIX}/bin

# derived from above parameters
INCLUDES = -I${PREFIX}/include -I../src
CCFLAGS = -W -Wfloat-equal -Wpointer-arith -Wcast-align -Wredundant-decls -Wendif-labels -Wshadow -pipe -ffast-math -U__STRICT_ANSI__ -g -O2 -arch i386 ${INCLUDES}
LIBDIR = ${PREFIX}/lib
LIBS = -lpbc -lgmp -lfenc
SSL = -lcrypto
TARGETS = benchmark

all: $(TARGETS)

benchmark: benchmark.o base64.o common.o
	$(CC) $(CCFLAGS) -o $@ $^ $(LIBS)

install:
	mkdir -p $(INSTALLDIR)
	install -m 755 $(TARGETS) $(INSTALLDIR)
clean:
	rm -rf $(TARGETS) *.o

%.o: %.c
	$(CC) $(CCFLAGS) -c $<


