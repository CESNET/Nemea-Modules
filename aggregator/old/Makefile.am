bin_PROGRAMS=aggregator
aggregator_SOURCES=aggregator.c aggregator.h timedb.c timedb.h fields.c fields.h
aggregator_LDADD=-ltrap -lunirec -lurfilter -lnemea-common -lcrypto
aggregator_CPPFLAGS=-I${top_srcdir}/unirecfilter/lib
aggregator_LDFLAGS=-L${top_builddir}/unirecfilter/lib
pkgdocdir=${docdir}/aggregator
pkgdoc_DATA=README.md
EXTRA_DIST=README.md
include ../aminclude.am
