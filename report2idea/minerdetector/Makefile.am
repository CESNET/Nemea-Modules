bin_SCRIPTS=minerdetector2idea.py
TESTS=test.sh

confdir=${sysconfdir}/warden/minerdetector
conf_DATA=config.cfg

supdir=${nemeasupdir}/reporters
sup_DATA=miner2idea.sup

EXTRA_DIST=${bin_SCRIPTS} ${TESTS} ${conf_DATA} ${sup_DATA}

clean-local:
	rm -f *.idea

