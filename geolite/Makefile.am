EXTRA_DIST=geolite.py readme.md
bin_SCRIPTS=geolite.py

pkgdocdir=${docdir}/geolite
pkgdoc_DATA=readme.md

pylint:
	pylint-3 geolite.py

flake8:
	flake8 geolite.py

pycodestyle:
	pycodestyle-3 geolite.py

lint: pylint flake8 pycodestyle

include ../aminclude.am