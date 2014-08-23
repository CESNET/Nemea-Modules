bin_PROGRAMS=unirecfilter
unirecfilter_SOURCES=unirecfilter.c \
                     ./bison/parser.tab.c \
                     ./bison/lex.yy.c \
                     ./bison/functions.c
BUILT_SOURCES=./bison/parser.tab.c
unirecfilter_LDADD=-ltrap -lunirec
pkgdocdir=${docdir}/unirecfilter
pkgdoc_DATA=README
SUBDIRS = bison
./bison/parser.tab.c: bison

