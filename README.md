# r4ghidra

[![Build Extension](https://github.com/radareorg/ghidra-r2web/actions/workflows/gradle.yml/badge.svg)](https://github.com/radareorg/ghidra-r2web/actions/workflows/gradle.yml)

This repository contains integration scripts to interop Ghidra and radare2.

It's just an Ghidra plugin that starts an http server to let r2 talk to it.

## Features

* Decompile current function
* Load the decompiler output as comments
* List functions found by Ghidra ('afl')
* List symbols 'is' from Ghidra bin parser
* Import comments from Ghidra into r2
* Read/Write ghidra's session remote memory contents

## Usage

* Install Ghidra using r2pm or downloading it from the web

```bash
$ r2pm -i ghidra
```

* Symlink the R4GhidraScript.java into the ghidra plugins directory

```bash
$ make install
````

* Start ghidra and doubleclick the script to get the http server

```bash
$ r2pm -r ghidraRun
```

* Attach r2 to the ghidra session

```bash
$ r2 r2web://localhost:8002/cmd
```

* Run commands into the ghidra server from r2 or the shell

	* :pdd
	* !curl http://localhost:8002/cmd/p8%2080

## Sample session

```bash
$ r2 r2web://localhost:9191/cmd
[0x00000000]> :?
Usage: [ghidra-r2web-command .. args]
?             - show this help message
?V            - show Ghidra Version information
?p [vaddr]    - get physical address for given virtual address
f [name]      - set flag to the current offset inside ghidra (label)
i             - show program information (arch/bits/hash..)
/ [string]    - search for given string (which may contain \x hex)
s ([addr])    - check or set current seek address
b ([bsize])   - get or set blocksize
CC [comment]  - add or replace comment in current offset
Cs            - define a string in the current address
Cd            - define a dword in the current address
aa            - analyze all the program
af            - analyze function in current address
afi           - get current function information
afl           - list all functions analyzed by Ghidra
px            - print Hexdump
pdd           - print decompilation of current function
pdd*          - decompile current function as comments for r2
q             - quit the ghidra-r2web script
[0x00000000]> \?V
9.0.4
[0x00000000]>
```

--pancake
