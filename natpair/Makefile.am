ACLOCAL_AMFLAGS = -I m4
bin_PROGRAMS=natpair
natpair_SOURCES=natpair.cpp natpair.h fields.c fields.h
natpair_LDADD=-lunirec -ltrap -lpthread
natpair_CXXFLAGS=-std=c++0x

EXTRA_DIST=README.md
pkgdocdir=${docdir}/natpair
pkgdoc_DATA=README.md

include ../aminclude.am
