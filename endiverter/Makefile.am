include ../aminclude.am

bin_PROGRAMS=endiverter
endiverter_SOURCES=endiverter.c

endiverter_LDADD=-ltrap -lunirec
endiverter_CFLAGS=-Wall

endiverter.1: endiverter.c
	$(TRAP2MAN) endiverter.c > endiverter.1

man_MANS=endiverter.1

CLEANFILES+=endiverter.1
