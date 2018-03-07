ACLOCAL_AMFLAGS = -I m4
bin_PROGRAMS=aggregation_module
aggregation_module_SOURCES=aggregation_module.cpp key.cpp key.h output.cpp output.h agg_functions.h agg_functions.cpp  configuration.h configuration.cpp fields.c fields.h
aggregation_module_LDADD=-lunirec -ltrap
aggregation_module_CXXFLAGS=-std=c++11 -g
include ./aminclude.am
