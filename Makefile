FCNADDR=1000011e8
TESTBIN=$(shell pwd)/test/ls
SCRIPT=R4GhidraServer.java

all:
	$(MAKE) -C R4Ghidra

oops:
	analyzeHeadless . Test.gpr -import $(TESTBIN) -postScript $(SCRIPT) $(FCNADDR) -deleteProject
	r2 -caf -i ghidra-output.r2 $(TESTBIN)

R2PM_BINDIR=$(shell r2pm -H R2PM_BINDIR)

install:
	ln -fs $(shell pwd)/r2g $(R2PM_BINDIR)/r2g
	mkdir -p ~/ghidra_scripts
	ln -fs $(shell pwd)/$(SCRIPT) ~/ghidra_scripts/$(SCRIPT)

#ln -fs $(shell pwd)/R2GhidraServerSingleton.java ~/ghidra_scripts/R2GhidraServerSingleton.java

uninstall:
	rm -f $(R2PM_BINDIR)/r2g

GJF=google-java-format-1.7-all-deps.jar

$(GJF):
	wget https://github.com/google/google-java-format/releases/download/google-java-format-1.7/google-java-format-1.7-all-deps.jar

indent: $(GJF)
	java -jar $(GJF) -i *.java */*.java
