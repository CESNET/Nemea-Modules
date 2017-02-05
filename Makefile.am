ACLOCAL_AMFLAGS = -I m4

SUBDIRS=anonymizer \
debug_sender \
device_classifier \
email_reporter \
flowcounter \
json_dump \
json_replay \
link_traffic \
logger \
logreplay \
merger \
proto_traffic \
report2idea \
traffic_repeater \
unirec2json \
endiverter

EXTRA_DIST = AUTHORS COPYING ChangeLog INSTALL NEWS README.md nfreader

if HAVE_LIBNF
SUBDIRS += nfreader
SUBDIRS += nfwriter
endif

if HAVE_BISON
SUBDIRS += unirecfilter aggregator
endif

if HAVE_LIBPCAP
SUBDIRS += flow_meter
endif

RPMDIR = RPMBUILD

if MAKE_RPMS
RPMFILENAME=$(PACKAGE_NAME)-$(VERSION)
.PHONY: srpm
srpm:
	rm -rf "$(RPMDIR)/SOURCES/$(RPMFILENAME)"
	mkdir -p $(RPMDIR)/BUILD/ $(RPMDIR)/SRPMS/ $(RPMDIR)/RPMS/ $(RPMDIR)/SOURCES
	make ${AM_MAKEFLAGS} distdir='$(RPMDIR)/SOURCES/$(RPMFILENAME)' distdir
	( cd "$(RPMDIR)/SOURCES/"; tar -z -c -f $(RPMFILENAME)-$(RELEASE).tar.gz $(RPMFILENAME); rm -rf $(RPMFILENAME); )
	$(RPMBUILD) -bs $(PACKAGE_NAME).spec --define "_topdir `pwd`/$(RPMDIR)";

.PHONY: rpm
rpm: srpm
	$(RPMBUILD) --define "_topdir `pwd`/$(RPMDIR)" --rebuild $(RPMDIR)/SRPMS/$(RPMFILENAME)-$(RELEASE).src.rpm;
else
endif

rpm-clean:
	rm -rf $(RPMDIR)
