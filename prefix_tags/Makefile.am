bin_PROGRAMS=prefix_tags

# Devel
# prefix_tags_CFLAGS=-g -O0 -fsanitize=address -fno-omit-frame-pointer -DDEBUG=1

prefix_tags_SOURCES=\
	prefix_tags.c prefix_tags.h \
	prefix_tags_config.c prefix_tags_config.h \
	prefix_tags_functions.c prefix_tags_functions.h \
	fields.c fields.h
prefix_tags_LDADD=-ltrap -lunirec

pkgdocdir=${docdir}/prefix_tags
dist_pkgdoc_DATA=README.md

# Tests
noinst_PROGRAMS = test_prefix_tags
TESTS = test_prefix_tags

test_prefix_tags_SOURCES = \
	test_prefix_tags.c \
	prefix_tags_functions.c prefix_tags_functions.h

test_prefix_tags_LDADD=-lunirec

include ../aminclude.am

