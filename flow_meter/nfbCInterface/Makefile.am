SUBDIRS=.
lib_LTLIBRARIES=libndpRI.la

include_HEADERS=include/ndpreader.hpp \
		include/ndpheader.h \
		include/ndpreader.h

libndpRI_src=ndpreader.cpp \
	     ndpheader.cpp

libndpRI_la_SOURCES=$(libndpRI_src)

libndpRI_la_LIBADD= -lnuma -lnfb -lpcap
libndpRI_la_CXXFLAGS= -I include -std=c++98 -Wno-write-strings

METASOURCES = AUTO
