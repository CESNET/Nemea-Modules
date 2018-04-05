bin_PROGRAMS=scalar_agg
scalar_agg_SOURCES=aggregator.c aggregator.h timedb.c timedb.h fields.c fields.h
scalar_agg_LDADD=-ltrap -lunirec -lurfilter -lnemea-common -lcrypto
scalar_agg_CPPFLAGS=-I${top_srcdir}/unirecfilter/lib
scalar_agg_LDFLAGS=-L${top_builddir}/unirecfilter/lib
pkgdocdir=${docdir}/scalar_agg
pkgdoc_DATA=README.md
EXTRA_DIST=README.md
include ../aminclude.am
