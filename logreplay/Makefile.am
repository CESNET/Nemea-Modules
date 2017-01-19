include ../aminclude.am

bin_PROGRAMS=logreplay
logreplay_SOURCES=logreplay.cpp fields.c fields.h
logreplay_LDADD=-lunirec -ltrap
logreplay_CXXFLAGS=-O2 -std=c++98 -Wno-write-strings
pkgdocdir=${docdir}/logreplay
pkgdoc_DATA=README.md
EXTRA_DIST=README.md

mansources := $(addprefix $(srcdir)/,$(logreplay_SOURCES))
logreplay.1: $(mansources)
	$(TRAP2MAN) $^ > $@

man_MANS=logreplay.1

CLEANFILES+=logreplay.1
