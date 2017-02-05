bin_SCRIPTS=dnstunnel2idea.py
TESTS=test.sh

confdir=${sysconfdir}/warden/dnstunnel
conf_DATA=config.cfg

supdir=${nemeasupdir}/reporters
sup_DATA=dnstunnel2idea.sup

EXTRA_DIST=${bin_SCRIPTS} ${TESTS} ${conf_DATA} ${sup_DATA}

clean-local:
	rm -f *.idea

