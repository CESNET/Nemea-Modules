include ../aminclude.am

bin_PROGRAMS=endiverter
endiverter_SOURCES=endiverter.c

endiverter_LDADD=-ltrap -lunirec
endiverter_CFLAGS=-Wall

mansources := $(addprefix $(srcdir)/,$(endiverter_SOURCES))
endiverter.1: $(mansources)
	$(TRAP2MAN) $^ > $@

man_MANS=endiverter.1

CLEANFILES+=endiverter.1
