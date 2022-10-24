ACLOCAL_AMFLAGS = -I m4
bin_PROGRAMS=biflow_aggregator
biflow_aggregator_SOURCES=main.cpp \
	aggregatorConfigParser.hpp \
	aggregatorConfigParser.cpp \
	aggregatorConfigParserFactory.hpp \
	aggregatorConfigParserFactory.cpp \
	aggregatorConfigParserFactoryRegistrator.hpp \
	config.hpp \
	config.cpp \
	libtrapAdapter.hpp \
	libtrapAdapter.cpp \
	unirecAdapter.hpp \
	unirecAdapter.cpp \
	xmlAggregatorConfigParser.hpp \
	xmlAggregatorConfigParser.cpp \
	flowKeyUnirecDescription.hpp \
	flowKeyUnirecDescription.cpp
biflow_aggregator_LDADD=-lunirec -ltrap -lpugixml
biflow_aggregator_CXXFLAGS=-std=gnu++17
include ../aminclude.am
