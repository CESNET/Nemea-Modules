include ../aminclude.am

bin_PROGRAMS=nfwriter

nfwriter_SOURCES=nfwriter.c fields.c fields.h
nfwriter_LDADD=-lunirec -ltrap -lnf
nfwriter_CFLAGS=-Wall -g

EXTRA_DIST=README.md
pkgdocdir=${docdir}/nfwriter
pkgdoc_DATA=README.md

