bin_PROGRAMS=logreplay
logreplay_SOURCES=logreplay.cpp fields.c fields.h
logreplay_LDADD=-lunirec -ltrap
logreplay_CXXFLAGS=-std=c++98 -Wno-write-strings
pkgdocdir=${docdir}/logreplay
pkgdoc_DATA=README.md
EXTRA_DIST=README.md
include ../aminclude.am
