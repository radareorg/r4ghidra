ifneq ($(shell test -d /snap/ghidra/current && echo snap),)
GHIDRA_PATH=/snap/ghidra/current
else
ifneq ($(shell test -f /var/lib/flatpak/app/org.ghidra_sre.Ghidra/current/active/files/lib/ghidra && flatpak),)
GHIDRA_PATH=/var/lib/flatpak/app/org.ghidra_sre.Ghidra/current/active/files/lib/ghidra
else
GHIDRA_PATH=$(HOME)/Downloads
endif
endif

GHIDRA_HOME=$(shell cd $(GHIDRA_PATH) ; ls -rt 2> /dev/null | grep ^ghidra_ |grep -v zip | tail -n 1)
GHIDRA_INSTALL_DIR?=$(HOME)/Downloads/$(GHIDRA_HOME)

ifeq ($(GHIDRA_INSTALL_DIR),)
all:
	@echo Cannot find Ghidra in $(GHIDRA_PATH) or GHIDRA_INSTALL_DIR

else
GHIDRA_INSTALL_DIR?=$(HOME)/Downloads/$(GHIDRA_HOME)
all:
	GHIDRA_INSTALL_DIR="$(GHIDRA_INSTALL_DIR)" gradle buildExtension
endif

javadoc doc:
	GHIDRA_INSTALL_DIR="$(GHIDRA_INSTALL_DIR)" gradle javadoc

install: uninstall
	cp -f dist/"$(shell ls -rt dist |grep zip | tail -n1)" $(GHIDRA_INSTALL_DIR)/Extensions/Ghidra

uninstall:
	rm -f "$(GHIDRA_INSTALL_DIR)/Extensions/Ghidra/ghidra"_*R4G*
	rm -rf $(HOME)/.config/ghidra/ghidra_*/Extensions/R4Ghidra

# XXX not working
headless:
	$(GHIDRA_PATH)/support/analyzeHeadless /tmp/ test -process /bin/ls -postScript ghidra_scripts/r4ghidra_headless.py 

run:
	$(GHIDRA_INSTALL_DIR)/ghidraRun

clean:
	rm -rf .gradle dist build

indent:
	$(MAKE) -C .. indent
#	GHIDRA_INSTALL_DIR="$(GHIDRA_INSTALL_DIR)" gradle spotlessApply

mrproper: clean
	rm -rf "$(HOME)/.gradle"

.PHONY: all clean mrproper indent headless
