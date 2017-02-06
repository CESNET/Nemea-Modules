ACLOCAL_AMFLAGS = -I m4
bin_PROGRAMS=topn
topn_SOURCES=topn.c topn.h fields.c fields.h twister.h
topn_LDADD=-lunirec -ltrap
EXTRA_DIST=README.md
pkgdocdir=$(docdir)/topn
pkgdoc_DATA=README.md
include ../aminclude.am
