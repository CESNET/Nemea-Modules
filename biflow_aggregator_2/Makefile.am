ACLOCAL_AMFLAGS = -I m4
bin_PROGRAMS=biflow_aggregator
biflow_aggregator_SOURCES=main.cpp \
	aggregatorConfigParser.hpp \
	aggregatorConfigParser.cpp \
	aggregatorConfigParserFactory.hpp \
	aggregatorConfigParserFactory.cpp
biflow_aggregator_LDADD=-lunirec -ltrap
biflow_aggregator_CXXFLAGS=-std=gnu++17
include ../aminclude.am
