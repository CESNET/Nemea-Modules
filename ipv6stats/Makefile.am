bin_PROGRAMS=ipv6stats
ipv6stats_SOURCES=ipv6stats.cpp ipv6stats.h fields.c fields.h
ipv6stats_LDADD=-ltrap -lunirec
ipv6stats_CXXFLAGS=-std=c++98 -Wno-write-strings
pkgdocdir=${docdir}/ipv6stats
pkgdoc_DATA=README.md
EXTRA_DIST=README.md
include ../aminclude.am
