SHELL := /bin/sh
.DEFAULT_GOAL := help

VERSION ?= 0.1.0-rc.1
ARTIFACT := $(CURDIR)/.workspace/dist/flowgate-$(VERSION)-linux-x86_64.tar.gz
BUNDLE ?= $(ARTIFACT)
SHA256 ?=
DESKTOP_FLAGS ?= --migrate-autostart
INSTALL_FLAGS ?=
RECOVER_FLAGS ?=
UNDESKTOP_FLAGS ?= --migrate-autostart
INSTALL_FLAGS ?=

.PHONY: help build check package preflight install desktop recover uninstall clean
help:
	@printf '%s\n' 'make build        Build the daemon, desktop and helpers' \
	  'make check        Run focused release checks' \
	  'make package      Create an offline installer bundle and SHA256 receipt' \
	  'make preflight    Check a package against the installed state' \
	  'make install      Install a verified package (BUNDLE=... SHA256=...)' \
	  'make desktop      Migrate the current user login or import preferences' \
	  'make recover      Restore monitoring (RECOVER_FLAGS=--rollback for rollback)' \
	  'make uninstall    Remove FlowGate (UNINSTALL_FLAGS=--purge to delete data)' \
	  'make clean        Remove only this checkout’s generated release artifacts'

build:
	scripts/build-standalone.sh

check:
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/test-standalone-release.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/test-standalone-freshness.py

package: build check
	python3 -B deployment/standalone/package.py "$(VERSION)" "$(ARTIFACT)"

preflight install:
	@test -n "$(SHA256)" || { printf '%s\n' 'Set SHA256 to the verified package digest'; exit 2; }
	sudo /usr/bin/python3 -I -B "$(CURDIR)/deployment/standalone/release.py" $@ \
	  --bundle "$(BUNDLE)" --sha256 "$(SHA256)" $(INSTALL_FLAGS)

desktop:
	/usr/local/bin/flowgate-ui $(DESKTOP_FLAGS)

recover:
	sudo /usr/local/sbin/flowgate-recover $(RECOVER_FLAGS)

uninstall:
	sudo /usr/local/sbin/flowgate-uninstall $(UNINSTALL_FLAGS)

clean:
	rm -rf -- .workspace/standalone-build .workspace/dist
