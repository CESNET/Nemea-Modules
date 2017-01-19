include ../aminclude.am

bin_PROGRAMS=merger
merger_SOURCES=merger.c fields.c fields.h
merger_LDADD=-lunirec -ltrap
merger_CFLAGS=${OPENMP_CFLAGS}

EXTRA_DIST=README.md
pkgdocdir=${docdir}/merger
pkgdoc_DATA=README.md

mansources := $(addprefix $(srcdir)/,$(merger_SOURCES))
merger.1: $(mansources)
	$(TRAP2MAN) $^ > $@

man_MANS=merger.1

CLEANFILES+=merger.1
