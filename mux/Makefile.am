bin_PROGRAMS=mux
mux_SOURCES=mux.cpp 
mux_LDADD=-lunirec -ltrap
mux_LDFLAGS=-fopenmp
mux_CFLAGS=${OPENMP_CFLAGS}
EXTRA_DIST=README.md
pkgdocdir=${docdir}/mux
pkgdoc_DATA=README.md
include ../aminclude.am
