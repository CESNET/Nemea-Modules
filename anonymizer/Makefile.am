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
anonymizer_LDADD=-ltrap -lunirec -lnemea-common
pkgdocdir=${docdir}/anonymizer
pkgdoc_DATA=README
