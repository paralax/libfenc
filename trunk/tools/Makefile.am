#
#
# LIBFENC -- The Functional Encryption Library
#
#-------------------------------------------------------------------------------------------

# Have configure setup a Makefile in a subdirectory.
SUBDIRS = .

# Maintain a pretty and effective make clean.
CLEANFILES = *~
maintainer-clean-local:
	-rm -rf Makefile.in
	
# Link in those libraries. Can't use -lfenc yet.
AM_LDFLAGS = -lgmp -lpbc -lcrypto
AM_CPPFLAGS = -I/usr/local/include -I/usr/include -I../
LDADD = ../libfenc.la

bin_PROGRAMS = abe-setup abe-keygen abe-enc abe-dec policy-test

abe_setup_SOURCES = mgabe-setup.c base64.c base64.h \
		    common.c common.h
abe_keygen_SOURCES = mgabe-keygen.c base64.c common.c
abe_enc_SOURCES = mgabe-enc.c base64.c common.c
abe_dec_SOURCES = mgabe-dec.c base64.c common.c
policy_test_SOURCES = policy-tool.c common.c


