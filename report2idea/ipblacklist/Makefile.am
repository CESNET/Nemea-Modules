bin_SCRIPTS=ipblacklist2idea.py urlblacklist2idea.py
TESTS=test.sh

confdir=${sysconfdir}/warden/ipblacklist
conf_DATA=config.cfg

supdir=${nemeasupdir}/reporters
sup_DATA=ipblacklist2idea.sup urlblacklist2idea.sup

EXTRA_DIST=${bin_SCRIPTS} ${TESTS} ${conf_DATA} ${sup_DATA}

clean-local:
	rm -f *.idea

