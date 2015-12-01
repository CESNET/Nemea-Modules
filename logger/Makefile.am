include ../aminclude.am

bin_PROGRAMS=logger
logger_SOURCES=logger.c fields.c fields.h
logger_CFLAGS=-fopenmp
logger_LDADD=-lunirec -ltrap
logger_LDFLAGS=-fopenmp

pkgdocdir=${docdir}/logger
pkgdoc_DATA=README.md
EXTRA_DIST=README.md

