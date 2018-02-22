bin_SCRIPTS=vportscan2idea.py
TESTS=test.sh

confdir=${sysconfdir}/warden/vportscan
conf_DATA=config.cfg

supdir=${nemeasupdir}/reporters
sup_DATA=vportscan2idea.sup

EXTRA_DIST=${bin_SCRIPTS} ${TESTS} ${conf_DATA} ${sup_DATA}

clean-local:
	rm -f *.idea

