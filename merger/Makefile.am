bin_PROGRAMS=merger
merger_SOURCES=merger.c fields.c fields.h
merger_LDADD=-lunirec -ltrap
merger_CFLAGS=${OPENMP_CFLAGS}
EXTRA_DIST=README.md
pkgdocdir=${docdir}/merger
pkgdoc_DATA=README.md
include ../aminclude.am
