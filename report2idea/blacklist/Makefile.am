bin_SCRIPTS=blacklist2idea.py
TESTS=test.sh

confdir=${sysconfdir}/warden/blacklist
conf_DATA=config.cfg

supdir=${nemeasupdir}/reporters
sup_DATA=blacklist2idea.sup

EXTRA_DIST=${bin_SCRIPTS} ${TESTS} ${conf_DATA} ${sup_DATA}

clean-local:
	rm -f *.idea

