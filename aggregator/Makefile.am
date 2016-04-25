include ../aminclude.am

bin_PROGRAMS=aggregator
aggregator_SOURCES=aggregator.c aggregator.h timedb.c timedb.h fields.c fields.h
aggregator_LDADD=-ltrap -lunirec -lurfilter -lnemea-common
aggregator_CPPFLAGS=-I../unirecfilter/lib
aggregator_LDFLAGS=-L../unirecfilter/lib
pkgdocdir=${docdir}/aggregator
pkgdoc_DATA=README.md
EXTRA_DIST=README.md
