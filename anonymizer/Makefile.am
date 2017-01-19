include ../aminclude.am

bin_PROGRAMS=anonymizer
anonymizer_SOURCES=anonymizer.c \
                   anonymizer.h \
                   fields.c \
                   fields.h \
                   panonymizer.c \
                   panonymizer.h \
                   rijndael.c \
                   rijndael.h
# There is lot of strict-aliasing warningis in rijndael.c, disable it
anonymizer_CFLAGS=-fno-strict-aliasing
anonymizer_LDADD=-ltrap -lunirec -lnemea-common
pkgdocdir=${docdir}/anonymizer
pkgdoc_DATA=README

anonymizer.1: anonymizer.c
	$(TRAP2MAN) anonymizer.c > anonymizer.1

man_MANS=anonymizer.1

CLEANFILES+=anonymizer.1
