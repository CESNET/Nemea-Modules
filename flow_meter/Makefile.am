include ../aminclude.am

SUBDIRS=. tests

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
		    sipplugin.cpp \
		    sipplugin.h \
		    fields.c \
		    fields.h \
		    dnsplugin.cpp \
		    dnsplugin.h \
		    ntpplugin.cpp \
		    ntpplugin.h \
		    ipaddr.h \
		    arpplugin.cpp \
		    arpplugin.h


flow_meter_LDADD=-ltrap -lunirec -lnemea-common -lpcap
flow_meter_CXXFLAGS=-std=c++98 -Wno-write-strings
pkgdocdir=${docdir}/flow_meter
pkgdoc_DATA=README.md
EXTRA_DIST=README.md traffic-samples/arp-sample.pcap traffic-samples/dns-sample.pcap traffic-samples/http-sample.pcap traffic-samples/ntp-sample.pcap traffic-samples/sip-sample.pcap

mansources := $(addprefix $(srcdir)/,$(flow_meter_SOURCES))
flow_meter.1: $(mansources)
	$(TRAP2MAN) $^ > $@

man_MANS=flow_meter.1

CLEANFILES+=flow_meter.1

bashcompl_DATA=flow_meter.bash
