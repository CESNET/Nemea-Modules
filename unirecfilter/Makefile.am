include ../aminclude.am

SUBDIRS = lib

bin_PROGRAMS=unirecfilter
unirecfilter_SOURCES=unirecfilter.c \
                     unirecfilter.h \
                     fields.c \
                     fields.h
unirecfilter_LDADD=-ltrap -lunirec -lurfilter
unirecfilter_CPPFLAGS=-I${top_srcdir}/unirecfilter/lib
unirecfilter_LDFLAGS=-L${top_builddir}/unirecfilter/lib
pkgdocdir=${docdir}/unirecfilter
pkgdoc_DATA=README.md
EXTRA_DIST=README.md

mansources := $(addprefix $(srcdir)/,$(unirecfilter_SOURCES))
unirecfilter.1: $(mansources)
	$(TRAP2MAN) $^ > $@

man_MANS=unirecfilter.1

CLEANFILES+=unirecfilter.1
