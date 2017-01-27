include ../aminclude.am

bin_PROGRAMS=nfdump_reader nfdump_reader_test

nfdump_reader_test_SOURCES=nfdump_reader_test.cpp fields.c fields.h
nfdump_reader_SOURCES=nfdump_reader.c fields.c fields.h

LDADD=-lunirec -ltrap -lnf

nfdump_reader_test_CXXFLAGS=-Wno-write-strings

EXTRA_DIST=README.md
pkgdocdir=${docdir}/nfreader
pkgdoc_DATA=README.md

mansources := $(addprefix $(srcdir)/,$(nfdump_reader_SOURCES))
nfdump_reader.1: $(mansources)
	$(TRAP2MAN) $^ > $@

man_MANS=nfdump_reader.1

CLEANFILES+=nfdump_reader.1
