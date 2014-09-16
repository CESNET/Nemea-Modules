FLEX = flex
BISON = bison

bin_PROGRAMS=unirecfilter
unirecfilter_SOURCES=unirecfilter.c \
                     parser.tab.c \
                     parser.tab.h \
                     lex.yy.c \
                     ./bison/functions.c
BUILT_SOURCES=parser.tab.c parser.tab.h lex.yy.c
unirecfilter_LDADD=-ltrap -lunirec
pkgdocdir=${docdir}/unirecfilter
pkgdoc_DATA=README

EXTRA_DIST=bison/functions.c bison/parser.y bison/scanner.l

all: parser.tab.c lex.yy.c

lex.yy.c: bison/scanner.l parser.tab.h
	$(FLEX) $<

parser.tab.h: parser.tab.c

parser.tab.c: bison/parser.y
	$(BISON) -d $<

clean-local:
	 rm -f lex.yy.c parser.tab.c parser.tab.h parser


