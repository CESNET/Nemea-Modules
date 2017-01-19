include ../aminclude.am

bin_PROGRAMS=flowcounter
flowcounter_SOURCES=flowcounter.c fields.c fields.h
flowcounter_LDADD=-ltrap -lunirec
pkgdocdir=${docdir}/flowcounter
pkgdoc_DATA=README.md
EXTRA_DIST=README.md

flowcounter.1: flowcounter.c
	$(TRAP2MAN) flowcounter.c > flowcounter.1

man_MANS=flowcounter.1

CLEANFILES+=flowcounter.1
