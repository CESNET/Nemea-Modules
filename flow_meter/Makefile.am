EXTRA_DIST=README.md

install-exec-local:
	ln -s /usr/bin/ipfixprobe $(DESTDIR)$(BINDIR)/flow_meter 2>/dev/null || true

uninstall-local:
	rm -f $(BINDIR)/flow_meter 2>/dev/null || true

clean-local:
	rm -f flow_meter

