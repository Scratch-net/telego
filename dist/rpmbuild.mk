## Creating an RPM distribution of the application.
## To build an RPM package, an installed RPM development environment is required.

RPMBUILD_DIST := ${MAKEFILE_DIR}dist
RPMBUILD_DIR  := ${MAKEFILE_DIR}.build/rpmbuild
RPMBUILD_OS   ?= $(RPMBUILD_OS:leap)
RPMBUILD_OS   ?= $(RPMBUILD_OS:tumbleweed)
RPMBUILD_VERN := $(shell echo "$(VERSION)" | awk -F '-' '{ print $$1 }' | sed 's/^v*//')
RPMBUILD_VERB := $(shell echo "$(VERSION)" | awk -F "$(RPMBUILD_VERN)-" '{ print $$2 }' | sed 's/-/./g' )

## Creating space for assembly without interfering with the operating system.
rpmbuild_make_workflow:
	@echo "Creating an RPMBUILD workspace."
	@mkdir -p ${RPMBUILD_DIR}/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}; true
.PHONY: rpmbuild_make_workflow

## Copying the necessary files to the workspace.
rpmbuild_copy_files: rpmbuild_make_workflow
	@echo "Copying files."
	@if [ -f "$(BINARY)" ]; \
		then mv -v -f "$(BINARY)" "${RPMBUILD_DIR}/SOURCES/telego"; \
	else \
		echo "File '$(BINARY)' not found."; \
		exit 1; \
	fi
	@if [ -f "$(MAKEFILE_DIR)config.example.toml" ]; \
		then cp -v -f "$(MAKEFILE_DIR)config.example.toml" ${RPMBUILD_DIR}/SOURCES/telego.toml; \
	else \
		echo "File '"$(MAKEFILE_DIR)config.example.toml"' not found."; \
		exit 1; \
	fi
	@cp -v -f "$(RPMBUILD_DIST)/rpmbuild.spec" "${RPMBUILD_DIR}/SPECS/telego.spec"
	@cp -v -f "$(RPMBUILD_DIST)/rpmbuild.service" "${RPMBUILD_DIR}/SOURCES/telego.service"
	@cp -v -f "$(RPMBUILD_DIST)/rpmbuild.sysconfig" "${RPMBUILD_DIR}/SOURCES/telego.sysconfig"
	@cp -v -f "$(RPMBUILD_DIST)/rpmbuild.logrotate" "${RPMBUILD_DIR}/SOURCES/telego.logrotate"
	@cp -v -f "$(RPMBUILD_DIST)/rpmbuild.permissions" "${RPMBUILD_DIR}/SOURCES/telego.permissions"
	@cp -v -f "$(RPMBUILD_DIST)/rpmbuild.tmpfilesd" "${RPMBUILD_DIR}/SOURCES/telego.tmpfilesd"
	@cp -v -f "$(RPMBUILD_DIST)/rpmbuild.target" "${RPMBUILD_DIR}/SOURCES/telego.target"
.PHONY: rpmbuild_copy_files

rpmbuild_environment_set:
	@echo "Making environment."
	@export RPMBUILD_OS=$(RPMBUILD_OS)
	@export RPMBUILD_OS=$(RPMBUILD_OS)
	@echo "- version: '$(RPMBUILD_VERN)'"
	@echo "- release build: '$(RPMBUILD_VERB)'"
.PHONY: rpmbuild_environment_set

## Building an RPM package.
rpm: build rpmbuild_copy_files rpmbuild_environment_set
	@echo "Building the RPM package."
	@RPMBUILD_OS="${RPMBUILD_OS}" rpmbuild \
		--target x86_64 \
		--define "debug_package %{nil}" \
		--define "_topdir ${RPMBUILD_DIR}" \
		--define "_app_version_number $(RPMBUILD_VERN)" \
		--define "_app_version_build $(RPMBUILD_VERB)" \
		-bb "${RPMBUILD_DIR}/SPECS/telego.spec"
	@cp -v "${RPMBUILD_DIR}/RPMS/x86_64/"*.rpm "${MAKEFILE_DIR}"
	@rm -rf "${MAKEFILE_DIR}.build"
.PHONY: rpm
