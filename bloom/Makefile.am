bin_PROGRAMS=bloom test_bloom

bloom_SOURCES=bloom.c bloom_functions.c bloom_functions.h fields.c fields.h
bloom_LDADD=-ltrap -lunirec
bloom_CFLAGS=-g

test_bloom_SOURCES=test_bloom.c bloom_functions.c bloom_functions.h fields.c fields.h
test_bloom_LDADD=-ltrap -lunirec
test_bloom_CFLAGS=-g -O0

pkgdocdir=${docdir}/bloom
pkgdoc_DATA=README.md
include ../aminclude.am
