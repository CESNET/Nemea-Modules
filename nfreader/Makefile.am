bin_PROGRAMS=nfdump_reader

if HAVE_LIBNFDUMP
bin_PROGRAMS+=nfdump_reader_test
nfdump_reader_test_SOURCES=nfdump_reader_test.cpp
endif

nfdump_reader_SOURCES=nfdump_reader.c
if HAVE_LIBNF
LDADD=-lunirec -ltrap -lnf
else
LDADD=-lunirec -ltrap -lnfdump
AM_CPPFLAGS=-DHAVE_LIBNFDUMP=1
endif
nfdump_reader_test_CXXFLAGS=-Wno-write-strings
include ../aminclude.am
