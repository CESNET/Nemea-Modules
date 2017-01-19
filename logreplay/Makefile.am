include ../aminclude.am

bin_PROGRAMS=logreplay
logreplay_SOURCES=logreplay.cpp fields.c fields.h
logreplay_LDADD=-lunirec -ltrap
logreplay_CXXFLAGS=-O2 -std=c++98 -Wno-write-strings
pkgdocdir=${docdir}/logreplay
pkgdoc_DATA=README.md
EXTRA_DIST=README.md

logreplay.1: logreplay.cpp
	$(TRAP2MAN) logreplay.cpp > logreplay.1

man_MANS=logreplay.1

CLEANFILES+=logreplay.1
