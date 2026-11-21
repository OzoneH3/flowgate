SHELL := /bin/sh
.DEFAULT_GOAL := help

BUNDLE ?=
IDENTITY := python3 -B deployment/standalone/identity.py
SHA256 ?=
DESKTOP_FLAGS ?= --migrate-autostart
INSTALL_FLAGS ?=
RECOVER_FLAGS ?=
UNINSTALL_FLAGS ?=

.PHONY: help build check identity archive-path package update preflight install desktop recover uninstall clean
help:
	@printf '%s\n' 'make build        Build the standalone daemon, Electron desktop and helpers' \
	  'make check        Run standalone package, lifecycle fixture and update-freshness checks' \
	  'make identity     Print the version, release ID and full source SHA' \
	  'make archive-path Print the archive path for this build identity' \
	  'make package      Build an archive, offline installer and SHA-256 receipts under build/dist/<release>/' \
	  'make update       Build this checkout, verify, preflight and install with sudo, then reload the desktop' \
	  'make preflight    Stage and check a package with sudo (SHA256=... required, BUNDLE=... optional)' \
	  'make install      Verify and install a package with sudo (SHA256=... required, BUNDLE=... optional)' \
	  'make desktop      Migrate login startup (DESKTOP_FLAGS selects other actions)' \
	  'make recover      Restore monitoring (RECOVER_FLAGS=--rollback selects a compatible predecessor)' \
	  'make uninstall    Remove FlowGate (UNINSTALL_FLAGS=--purge also removes system data and keeps user preferences)' \
	  'make clean        Delete the standalone build staging directory'

build:
	$(if $(filter-out undefined,$(origin VERSION) $(origin ARTIFACT)),$(error Version and archive name come from Git. Use a FlowGate release tag or build the current commit without VERSION or ARTIFACT))
	scripts/build-standalone.sh

identity:
	@$(IDENTITY)

archive-path:
	@$(IDENTITY) --field archive

check:
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/test-standalone-release.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/test-standalone-freshness.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/checks/test-standalone-identity.py

package: build check
	python3 -B deployment/standalone/package.py

update: package
	@set -eu; \
	  artifact="$$($(IDENTITY) --field archive)"; \
	  receipt="$$(basename "$$artifact").sha256"; \
	  (cd "$$(dirname "$$artifact")" && /usr/bin/sha256sum -c -- "$$receipt" flowgate-release.py.sha256); \
	  digest=$$(cut -d ' ' -f 1 "$$artifact.sha256"); \
	  $(MAKE) preflight BUNDLE="$$artifact" SHA256="$$digest"; \
	  $(MAKE) install BUNDLE="$$artifact" SHA256="$$digest"
	/usr/local/bin/flowgate-ui --reload-installed

preflight install:
	@test -n "$(SHA256)" || { printf '%s\n' 'Set SHA256 to the verified package digest'; exit 2; }
	@set -eu; bundle="$(BUNDLE)"; \
	  if [ -z "$$bundle" ]; then bundle="$$($(IDENTITY) --field archive)"; fi; \
	  sudo /usr/bin/python3 -I -B "$(CURDIR)/deployment/standalone/release.py" $@ \
	    --bundle "$$bundle" --sha256 "$(SHA256)" $(INSTALL_FLAGS)

desktop:
	/usr/local/bin/flowgate-ui $(DESKTOP_FLAGS)

recover:
	sudo /usr/local/sbin/flowgate-recover $(RECOVER_FLAGS)

uninstall:
	sudo /usr/local/sbin/flowgate-uninstall $(UNINSTALL_FLAGS)

clean:
	rm -rf -- build/standalone-build
