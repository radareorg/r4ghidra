FCNADDR=1000011e8
TESTBIN=$(shell pwd)/test/ls
SCRIPT=R4GhidraServer.java

all:
	$(MAKE) -C R4Ghidra

oops:
	analyzeHeadless . Test.gpr -import $(TESTBIN) -postScript $(SCRIPT) $(FCNADDR) -deleteProject
	r2 -caf -i ghidra-output.r2 $(TESTBIN)

clean mrproper:
	$(MAKE) -C R4Ghidra $@

R2PM_BINDIR=$(shell r2pm -H R2PM_BINDIR)

install:
	ln -fs $(shell pwd)/r2g $(R2PM_BINDIR)/r2g
	mkdir -p ~/ghidra_scripts
	ln -fs $(shell pwd)/$(SCRIPT) ~/ghidra_scripts/$(SCRIPT)
	$(MAKE) -C R4Ghidra install

uninstall:
	rm -f $(R2PM_BINDIR)/r2g
	$(MAKE) -C R4Ghidra uninstall

GJF_VERSION=1.28.0
GJF=google-java-format-$(GJF_VERSION)-all-deps.jar

gjf $(GJF):
	wget https://github.com/google/google-java-format/releases/download/v$(GJF_VERSION)/$(GJF)

indent: $(GJF)
	java -jar $(GJF) -i *.java */*.java \
		R4Ghidra/src/main/java/**/*.java
