FLEX = flex
BISON = bison
include ../aminclude.am
bin_PROGRAMS=unirecfilter
unirecfilter_SOURCES=unirecfilter.c \
                     unirecfilter.h \
                     parser.tab.c \
                     parser.tab.h \
                     lex.yy.c \
                     ./bison/functions.c \
                     fields.c \
                     fields.h
BUILT_SOURCES+=parser.tab.c parser.tab.h lex.yy.c fields.c fields.h
unirecfilter_LDADD=-ltrap -lunirec
pkgdocdir=${docdir}/unirecfilter
pkgdoc_DATA=README.md

EXTRA_DIST=bison/functions.c bison/parser.y bison/scanner.l README.md

all: parser.tab.c lex.yy.c

lex.yy.c: bison/scanner.l parser.tab.h
	$(FLEX) $<

parser.tab.h: parser.tab.c

parser.tab.c: bison/parser.y
	$(BISON) -d $<

clean-local:
	rm -f lex.yy.c parser.tab.c parser.tab.h parser fiedls.c fields.h

mansources := $(addprefix $(srcdir)/,$(unirecfilter_SOURCES))
unirecfilter.1: $(mansources)
	$(TRAP2MAN) $^ > $@

man_MANS=unirecfilter.1

CLEANFILES+=unirecfilter.1
