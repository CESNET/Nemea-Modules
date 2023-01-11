FLEX = flex
BISON = bison
include ../../aminclude.am
EXTRA_DIST=parser.y scanner.l test_liburfilter.c

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

if HAVE_CMOCKA
check_PROGRAMS=test_liburfilter
test_liburfilter_SOURCES=test_liburfilter.c
test_liburfilter_LDADD=-lcmocka -lurfilter
TESTS=test_liburfilter
endif

install-exec-hook:
	rm -f $(DESTDIR)$(libdir)/liburfilter.la

uninstall-hook:
	rm -f $(DESTDIR)$(libdir)/liburfilter.la $(DESTDIR)$(libdir)/liburfilter.a $(DESTDIR)$(libdir)/liburfilter.so.*

