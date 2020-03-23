.PHONY: clean all test build-deb build-deb-control build-deb-clean check-code format-code check-code

all: clean

clean:
	@echo "Remove __pycache__, .pytest_cache, .mypy_cache dirs."
	@find . -maxdepth 3 -name __pycache__ -type d -print | xargs rm -rf
	@find . -maxdepth 3 -name .pytest_cache -type d -print | xargs rm -rf
	@find . -maxdepth 3 -name .mypy_cache -type d -print | xargs rm -rf
	@echo "Done!"


test: clean
	pytest -v --cache-clear tests/


format-code:
	@black -l 100 -t py36 sslverify.py
	@black -l 100 -t py36 tests/test_basic.py
	@isort -rc tests
	@isort sslverify.py


check-code:
	@mypy sslverify.py
	@pylint -d C0330,C0103 sslverify.py

#++++++++++++++++++++++
# Deb package builder #
#++++++++++++++++++++++

DEB_PACKAGE_NAME := sslverify
DEB_PACKAGE_VERSION := Version: $(shell grep -o -P '(?<=version.=.").*(?=")' pyproject.toml)


build-deb-control:
	@mkdir -p ./$(DEB_PACKAGE_NAME)/DEBIAN/
	@echo "Package: sslverify\n\
	$(DEB_PACKAGE_VERSION)\n\
	Section: devel\n\
	Priority: optional\n\
	Architecture: all\n\
	Essential: no\n\
	Installed-Size: 10\n\
	Depends: python3\n\
	Maintainer: Alex Zh.\n\
	Description: Simple ssl certificate checker.\n\
	 MIT License.\
	" > ./$(DEB_PACKAGE_NAME)/DEBIAN/control


build-deb-clean:
	@rm -rf ./$(DEB_PACKAGE_NAME)
	@rm -f sslverify.deb


build-deb: build-deb-clean build-deb-control
	@mkdir -p ./$(DEB_PACKAGE_NAME)/usr/bin/
	@echo "#!/usr/bin/python3" >> ./$(DEB_PACKAGE_NAME)/usr/bin/sslverify
	@cat ./sslverify.py >> ./$(DEB_PACKAGE_NAME)/usr/bin/sslverify
	@chmod +x ./$(DEB_PACKAGE_NAME)/usr/bin/sslverify
	@dpkg-deb --build sslverify
