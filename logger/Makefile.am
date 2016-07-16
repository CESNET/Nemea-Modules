include ../aminclude.am

bin_PROGRAMS=logger
logger_SOURCES=logger.c fields.c fields.h
logger_CFLAGS=${OPENMP_CFLAGS}
logger_LDADD=-lunirec -ltrap

pkgdocdir=${docdir}/logger
pkgdoc_DATA=README.md
EXTRA_DIST=README.md

