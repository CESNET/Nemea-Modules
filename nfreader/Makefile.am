include ../aminclude.am

bin_PROGRAMS=nfdump_reader nfdump_reader_test

nfdump_reader_test_SOURCES=nfdump_reader_test.cpp fields.c fields.h
nfdump_reader_SOURCES=nfdump_reader.c fields.c fields.h

if HAVE_LIBNF
LDADD=-lunirec -ltrap -lnf
else
LDADD=-lunirec -ltrap -lnfdump
AM_CPPFLAGS=-DHAVE_LIBNFDUMP=1
endif

nfdump_reader_test_CXXFLAGS=-Wno-write-strings
