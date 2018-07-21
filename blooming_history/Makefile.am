bin_PROGRAMS=blooming_history test_blooming_history

blooming_history_SOURCES=blooming_history.c blooming_history_functions.c blooming_history_functions.h fields.c fields.h
blooming_history_LDADD=-ltrap -lunirec
blooming_history_CFLAGS=-g

test_blooming_history_SOURCES=test_blooming_history.c blooming_history_functions.c blooming_history_functions.h fields.c fields.h
test_blooming_history_LDADD=-ltrap -lunirec
test_blooming_history_CFLAGS=-g -O0

pkgdocdir=${docdir}/blooming_history
pkgdoc_DATA=README.md
include ../aminclude.am
