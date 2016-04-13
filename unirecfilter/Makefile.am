include ../aminclude.am

SUBDIRS = lib

bin_PROGRAMS=unirecfilter
unirecfilter_SOURCES=unirecfilter.c \
                     unirecfilter.h \
                     fields.c \
                     fields.h
unirecfilter_LDADD=-ltrap -lunirec -lurfilter
unirecfilter_CPPFLAGS=-I./lib
unirecfilter_LDFLAGS=-L./lib
pkgdocdir=${docdir}/unirecfilter
pkgdoc_DATA=README.md
