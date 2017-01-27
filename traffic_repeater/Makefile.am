bin_PROGRAMS=traffic_repeater
traffic_repeater_SOURCES=traffic_repeater.c traffic_repeater.h
traffic_repeater_LDADD=-ltrap -lrt
pkgdocdir=${docdir}/traffic_repeater
dist_pkgdoc_DATA=README.md

mansources := $(addprefix $(srcdir)/,$(traffic_repeater_SOURCES))
traffic_repeater.1: $(mansources)
	$(TRAP2MAN) $^ > $@

man_MANS=traffic_repeater.1

CLEANFILES=traffic_repeater.1
