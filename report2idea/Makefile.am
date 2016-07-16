bin_SCRIPTS=hoststats2idea.py \
			idea2idea.py \
			ipblacklist2idea.py \
			vportscan2idea.py \
			voipfraud2idea.py \
			dnstunnel2idea.py \
			bruteforce2idea.py \
			haddrscan2idea.py \
			amplification2idea.py

EXTRA_DIST=template.py test.sh ${bin_SCRIPTS}


tmpldatadir=${docdir}/report2idea
tmpldata_DATA=template.py

TESTS = test.sh

clean-local:
	rm -f *.idea

