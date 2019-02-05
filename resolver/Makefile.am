EXTRA_DIST=resolver.py readme.md pylintrc
bin_SCRIPTS=resolver.py

pkgdocdir=${docdir}/resolver
pkgdoc_DATA=readme.md

pylint:
	pylint-3 resolver.py

flake8:
	flake8 resolver.py

pycodestyle:
	pycodestyle-3 resolver.py

lint: pylint flake8 pycodestyle

include ../aminclude.am
