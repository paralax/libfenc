# Have configure setup a Makefile in a subdirectory.
SUBDIRS = .

# Maintain a pretty and effective make clean.
CLEANFILES = *~
maintainer-clean-local:
	-rm -rf Makefile.in ltmain.sh config.h.in configure \
	aclocal.m4 install-sh autom4te.cache

# Link in those libraries.
AM_LDFLAGS = -lgmp -lpbc -lcrypto -lfenc
AM_CPPFLAGS = -I/usr/local/include -I/usr/include

bin_PROGRAMS = abe-setup abe-keygen abe-enc abe-dec policy-test

abe_setup_SOURCES = mgabe-setup.c base64.c common.c
abe_keygen_SOURCES = mgabe-keygen.c base64.c common.c
abe_enc_SOURCES = mgabe-enc.c base64.c common.c
abe_dec_SOURCES = mgabe-dec.c base64.c common.c
policy_test_SOURCES = policy-tool.c common.c


