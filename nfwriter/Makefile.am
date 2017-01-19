include ../aminclude.am

bin_PROGRAMS=nfwriter

nfwriter_SOURCES=nfwriter.c fields.c fields.h
nfwriter_LDADD=-lunirec -ltrap -lnf
nfwriter_CFLAGS=-Wall

EXTRA_DIST=README.md
pkgdocdir=${docdir}/nfwriter
pkgdoc_DATA=README.md

mansources := $(addprefix $(srcdir)/,$(nfwriter_SOURCES))
nfwriter.1: $(mansources)
	$(TRAP2MAN) $^ > $@

man_MANS=nfwriter.1

CLEANFILES+=nfwriter.1
