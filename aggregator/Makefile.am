ACLOCAL_AMFLAGS = -I m4
bin_PROGRAMS=aggregator
aggregator_SOURCES=aggregator.cpp key.cpp key.h output.cpp output.h agg_functions.h agg_functions.cpp  configuration.h configuration.cpp fields.c fields.h
aggregator_LDADD=-lunirec -ltrap -lpthread
aggregator_CXXFLAGS=-std=c++98 -g
include ./aminclude.am
