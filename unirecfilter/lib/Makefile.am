FLEX = flex
BISON = bison
include ../../aminclude.am
EXTRA_DIST=parser.y scanner.l

lib_LTLIBRARIES = liburfilter.la
include_HEADERS = liburfilter.h
liburfilter_la_LDFLAGS = -version-info 1:0:1
liburfilter_la_SOURCES = liburfilter.c \
                     parser.tab.c \
                     parser.tab.h \
                     lex.yy.c \
                     functions.c \
                     functions.h \
                     fields.c \
                     fields.h
BUILT_SOURCES += parser.tab.c parser.tab.h lex.yy.c
pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = liburfilter.pc


#all: parser.tab.c lex.yy.c

lex.yy.c: scanner.l parser.tab.h
	$(FLEX) $<

parser.tab.h: parser.tab.c

parser.tab.c: parser.y
	$(BISON) -d $<

clean-local:
	rm -f lex.yy.c parser.tab.c parser.tab.h parser fiedls.c fields.h


