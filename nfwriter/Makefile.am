include ../aminclude.am

bin_PROGRAMS=nfwriter

nfwriter_SOURCES=nfwriter.c fields.c fields.h
nfwriter_LDADD=-lunirec -ltrap -lnf
nfwriter_CFLAGS=-Wall

EXTRA_DIST=README.md
pkgdocdir=${docdir}/nfwriter
pkgdoc_DATA=README.md

nfwriter.1: nfwriter.c
	$(TRAP2MAN) nfwriter.c > nfwriter.1

man_MANS=nfwriter.1

CLEANFILES+=nfwriter.1
