bin_SCRIPTS=voipfraud2idea.py
TESTS=test.sh

confdir=${sysconfdir}/warden/voipfraud
conf_DATA=config.cfg

supdir=${nemeasupdir}/reporters
sup_DATA=voipfraud2idea.sup

EXTRA_DIST=${bin_SCRIPTS} ${TESTS} ${conf_DATA} ${sup_DATA}

clean-local:
	rm -f *.idea

