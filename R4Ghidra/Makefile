ifeq ($(shell test -d /snap/ghidra/current),)
GHIDRA_PATH=/snap/ghidra/current
else
ifeq ($(shell test -f /var/lib/flatpak/app/org.ghidra_sre.Ghidra/current/active/files/lib/ghidra),)
GHIDRA_PATH=/var/lib/flatpak/app/org.ghidra_sre.Ghidra/current/active/files/lib/ghidra
else
GHIDRA_PATH=$(HOME)/Downloads
endif
endif

GHIDRA_INSTALL_DIR?=$(GHIDRA_PATH)/$(shell ls -rt $(GHIDRA_PATH) | grep ^ghidra_ | tail -n 1)

ifeq ($(GHIDRA_INSTALL_DIR),)
all:
	@echo Cannot find Ghidra in $(GHIDRA_PATH) or GHIDRA_INSTALL_DIR

else
GHIDRA_INSTALL_DIR?=$(HOME)/Downloads/$(GHIDRA_HOME)
all:
	GHIDRA_INSTALL_DIR="$(GHIDRA_INSTALL_DIR)" gradle buildExtension
endif

# XXX not working
headless:
	$(GHIDRA_PATH)/support/analyzeHeadless /tmp/ test -process /bin/ls -postScript ghidra_scripts/r4ghidra_headless.py 


clean:
	rm -rf .gradle dist build

indent:
	GHIDRA_INSTALL_DIR="$(GHIDRA_INSTALL_DIR)" gradle spotlessApply

mrproper: clean
	rm -rf "$(HOME)/.gradle"

.PHONY: all clean mrproper indent headless
