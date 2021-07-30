ACLOCAL_AMFLAGS = -I m4
bin_PROGRAMS=biflow_aggregator
biflow_aggregator_SOURCES=main.cpp fields.c fields.h configuration.cpp configuration.h key_template.cpp key_template.h \
                          aggregator.cpp aggregator.h xxhash.h macaddr.h linked_list.h flat_hash_map.h aggregator_functions.h \
                          rapidxml.hpp
biflow_aggregator_LDADD=-lunirec -ltrap
include ../aminclude.am
