SHELL := /bin/sh
.DEFAULT_GOAL := help

VERSION ?= 0.1.0-rc.7
ARTIFACT := $(CURDIR)/build/dist/flowgate-$(VERSION)-linux-x86_64.tar.gz
BUNDLE ?= $(ARTIFACT)
SHA256 ?=
DESKTOP_FLAGS ?= --migrate-autostart
INSTALL_FLAGS ?=
RECOVER_FLAGS ?=
UNINSTALL_FLAGS ?=

.PHONY: help build check package update preflight install desktop recover uninstall clean
help:
	@printf '%s\n' 'make build        Build the standalone daemon, Electron desktop and helpers' \
	  'make check        Run standalone package, lifecycle fixture and update-freshness checks' \
	  'make package      Write archive, flowgate-release.py and two .sha256 receipts to build/dist/ by default (VERSION=$(VERSION))' \
	  'make update       Build this checkout, verify, preflight and install with sudo, then reload the desktop' \
	  'make preflight    Stage and check a package with sudo (SHA256=... required, BUNDLE=... optional)' \
	  'make install      Verify and install a package with sudo (SHA256=... required, BUNDLE=... optional)' \
	  'make desktop      Migrate login startup (DESKTOP_FLAGS selects other actions)' \
	  'make recover      Restore monitoring (RECOVER_FLAGS=--rollback selects a compatible predecessor)' \
	  'make uninstall    Remove FlowGate (UNINSTALL_FLAGS=--purge also removes system data and keeps user preferences)' \
	  'make clean        Delete build/standalone-build/ and the entire build/dist/ directory'

build:
	scripts/build-standalone.sh

check:
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/test-standalone-release.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/test-standalone-freshness.py

package: build check
	python3 -B deployment/standalone/package.py "$(VERSION)" "$(ARTIFACT)"

update: package
	@set -eu; \
	  artifact="$(ARTIFACT)"; \
	  receipt="$$(basename "$$artifact").sha256"; \
	  (cd "$$(dirname "$$artifact")" && /usr/bin/sha256sum -c -- "$$receipt"); \
	  digest=$$(cut -d ' ' -f 1 "$$artifact.sha256"); \
	  $(MAKE) preflight BUNDLE="$$artifact" SHA256="$$digest"; \
	  $(MAKE) install BUNDLE="$$artifact" SHA256="$$digest"
	/usr/local/bin/flowgate-ui --reload-installed

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
	rm -rf -- build/standalone-build build/dist
