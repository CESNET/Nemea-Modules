ACLOCAL_AMFLAGS = -I m4
bin_PROGRAMS=backscatter
backscatter_SOURCES=backscatter.cpp backscatter.h backscatter_common.cpp backscatter_common.h EventTracker.cpp EventTracker.h FeatureVector.cpp FeatureVector.h fields.c fields.h
backscatter_LDADD=-lunirec -ltrap
backscatter_CXXFLAGS=--std=c++11 -O3 -pedantic -Werror -Wall
EXTRA_DIST=backscatter.sup
backscattersupdir=${nemeasupdir}/backscatter
backscattersup_DATA=backscatter.sup
include ../aminclude.am
