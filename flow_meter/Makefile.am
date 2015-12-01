include ../aminclude.am

bin_PROGRAMS=flow_meter
flow_meter_SOURCES=flow_meter.cpp \
		    flow_meter.h \
		    packet.h \
		    packetreceiver.h \
		    pcapreader.h \
		    flowexporter.h \
		    flowifc.h \
		    flowcache.h \
		    unirecexporter.h \
		    pcapreader.cpp \
		    nhtflowcache.cpp \
		    nhtflowcache.h \
		    unirecexporter.cpp \
		    stats.cpp \
		    stats.h \
		    flowcacheplugin.h \
		    httpplugin.cpp \
		    httpplugin.h \
		    fields.c \
		    fields.h \
		    dnsplugin.cpp \
		    dnsplugin.h


flow_meter_LDADD=-ltrap -lunirec -lpcap
flow_meter_CXXFLAGS=-O2 -std=c++98 -Wno-write-strings
pkgdocdir=${docdir}/flow_meter
pkgdoc_DATA=README.md
EXTRA_DIST=README.md
