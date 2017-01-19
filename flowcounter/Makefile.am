include ../aminclude.am

bin_PROGRAMS=flowcounter
flowcounter_SOURCES=flowcounter.c fields.c fields.h
flowcounter_LDADD=-ltrap -lunirec
pkgdocdir=${docdir}/flowcounter
pkgdoc_DATA=README.md
EXTRA_DIST=README.md


mansources := $(addprefix $(srcdir)/,$(flowcounter_SOURCES))
flowcounter.1: $(mansources)
	$(TRAP2MAN) $^ > $@

man_MANS=flowcounter.1

CLEANFILES+=flowcounter.1
