include ../aminclude.am

bin_PROGRAMS=merger
merger_SOURCES=merger.c fields.c fields.h
merger_LDADD=-lunirec -ltrap
merger_CFLAGS=${OPENMP_CFLAGS}

EXTRA_DIST=README.md
pkgdocdir=${docdir}/merger
pkgdoc_DATA=README.md

merger.1: merger.c
	$(TRAP2MAN) merger.c > merger.1

man_MANS=merger.1

CLEANFILES+=merger.1
