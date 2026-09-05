# Build the openSUSE x86_64 package. Keep the staging files for inspection.
RPMBUILD_DIST := $(MAKEFILE_DIR)dist
RPMBUILD_DIR := $(MAKEFILE_DIR).build/rpmbuild
RPMBUILD_VERSION := $(patsubst v%,%,$(VERSION))
RPMBUILD_VERN := $(firstword $(subst -, ,$(RPMBUILD_VERSION)))
ifneq ($(findstring -,$(RPMBUILD_VERSION)),)
RPMBUILD_VERB := $(subst -,.,$(patsubst $(RPMBUILD_VERN)-%,%,$(RPMBUILD_VERSION)))
else
RPMBUILD_VERB := $(shell date -u +%Y%m%d.%H%M%S.UTC)
endif
RPMBUILD_PACKAGE := telego-$(RPMBUILD_VERN)-$(RPMBUILD_VERB).x86_64.rpm

.PHONY: rpmbuild_make_workflow rpmbuild_copy_files rpmbuild_environment_set rpm

rpmbuild_make_workflow:
	@mkdir -p "$(RPMBUILD_DIR)/BUILD" "$(RPMBUILD_DIR)/BUILDROOT" \
		"$(RPMBUILD_DIR)/RPMS" "$(RPMBUILD_DIR)/SOURCES" \
		"$(RPMBUILD_DIR)/SPECS" "$(RPMBUILD_DIR)/SRPMS"

# Both prerequisites must finish before staging, including under make -j.
rpmbuild_copy_files: build rpmbuild_make_workflow
	cp -p "$(BINARY)" "$(RPMBUILD_DIR)/SOURCES/telego"
	cp -p "$(MAKEFILE_DIR)config.example.toml" "$(RPMBUILD_DIR)/SOURCES/telego.toml"
	cp -p "$(RPMBUILD_DIST)/rpmbuild.spec" "$(RPMBUILD_DIR)/SPECS/telego.spec"
	cp -p "$(RPMBUILD_DIST)/rpmbuild.service" "$(RPMBUILD_DIR)/SOURCES/telego.service"
	cp -p "$(RPMBUILD_DIST)/rpmbuild.sysconfig" "$(RPMBUILD_DIR)/SOURCES/telego.sysconfig"
	cp -p "$(RPMBUILD_DIST)/rpmbuild.logrotate" "$(RPMBUILD_DIR)/SOURCES/telego.logrotate"
	cp -p "$(RPMBUILD_DIST)/rpmbuild.permissions" "$(RPMBUILD_DIR)/SOURCES/telego.permissions"
	cp -p "$(RPMBUILD_DIST)/rpmbuild.tmpfilesd" "$(RPMBUILD_DIR)/SOURCES/telego.tmpfilesd"
	cp -p "$(RPMBUILD_DIST)/rpmbuild.target" "$(RPMBUILD_DIR)/SOURCES/telego.target"

rpmbuild_environment_set:
	@printf 'RPM version: %s\nRPM release: %s\n' "$(RPMBUILD_VERN)" "$(RPMBUILD_VERB)"

rpm: rpmbuild_copy_files rpmbuild_environment_set
	rpmbuild --target x86_64 \
		--define "_topdir $(RPMBUILD_DIR)" \
		--define "_app_version_number $(RPMBUILD_VERN)" \
		--define "_app_version_build $(RPMBUILD_VERB)" \
		-bb "$(RPMBUILD_DIR)/SPECS/telego.spec"
	cp -p "$(RPMBUILD_DIR)/RPMS/x86_64/$(RPMBUILD_PACKAGE)" "$(MAKEFILE_DIR)"
