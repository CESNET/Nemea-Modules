bin_SCRIPTS=hoststats2idea.py
TESTS=test.sh

confdir=${sysconfdir}/warden/hoststats
conf_DATA=config.cfg

supdir=${nemeasupdir}/reporters
sup_DATA=hoststats2idea.sup

EXTRA_DIST=${bin_SCRIPTS} ${TESTS} ${conf_DATA} ${sup_DATA}

clean-local:
	rm -f *.idea

