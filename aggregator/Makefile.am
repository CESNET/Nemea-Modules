ACLOCAL_AMFLAGS = -I m4
bin_PROGRAMS=agg
agg_SOURCES=aggregator.cpp key.cpp key.h output.cpp output.h agg_functions.h agg_functions.cpp configuration.h configuration.cpp fields.c fields.h
agg_LDADD=-lunirec -ltrap -lpthread
agg_CXXFLAGS=-std=c++11 -g
include ../aminclude.am
