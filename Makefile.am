ACLOCAL_AMFLAGS = -I m4

SUBDIRS=anonymizer \
debug_sender \
device_classifier \
email_reporter \
flowcounter \
json_dump \
json_replay \
logger \
logreplay \
merger \
report2idea \
traffic_repeater \
endiverter

EXTRA_DIST = AUTHORS COPYING ChangeLog INSTALL NEWS README.md nfreader

if HAVE_LIBNF
SUBDIRS += nfreader
else
if HAVE_LIBNFDUMP
SUBDIRS += nfreader
endif
endif

if HAVE_BISON
SUBDIRS += unirecfilter
endif

if HAVE_LIBPCAP
SUBDIRS += flow_meter
endif

RPMDIR = RPMBUILD

if MAKE_RPMS
RPMFILENAME=$(PACKAGE_NAME)-$(VERSION)
.PHONY: rpm
rpm:
	rm -rf "$(RPMDIR)/SOURCES/$(RPMFILENAME)"
	mkdir -p $(RPMDIR)/BUILD/ $(RPMDIR)/SRPMS/ $(RPMDIR)/RPMS/ $(RPMDIR)/SOURCES
	make ${AM_MAKEFLAGS} distdir='$(RPMDIR)/SOURCES/$(RPMFILENAME)' distdir
	( cd "$(RPMDIR)/SOURCES/"; tar -z -c -f $(RPMFILENAME)-$(RELEASE).tar.gz $(RPMFILENAME); rm -rf $(RPMFILENAME); )
	$(RPMBUILD) -ba $(PACKAGE_NAME).spec --define "_topdir `pwd`/$(RPMDIR)";

rpm-clean:
	rm -rf $(RPMDIR)
else
endif
