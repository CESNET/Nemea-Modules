bin_PROGRAMS=flow_meter
flow_meter_SOURCES=flow_meter.cpp \
		    flow_meter.h \
		    packet.h \
		    packetreceiver.h \
		    pcapreader.h \
		    flowifc.h \
		    flowcache.h \
		    flowwriter.h \
		    pcapreader.cpp \
		    mapflowcache.cpp \
		    mapflowcache.h \
		    nhtflowcache.cpp \
		    nhtflowcache.h \
		    flowwriter.cpp \
		    stats.cpp \
		    stats.h \
		    flowcacheplugin.h


flow_meter_LDADD=-ltrap -lunirec
pkgdocdir=${docdir}/flow_meter
pkgdoc_DATA=README
