# R4Ghidra Plugin

![r4ghidra-logo](doc/images/r4ghidra-logo2.jpg)

[![Build Extension](https://github.com/radareorg/r4ghidra/actions/workflows/gradle.yml/badge.svg)](https://github.com/radareorg/r4ghidra/actions/workflows/gradle.yml)

R4Ghidra provides a standalone radare2 experience inside Ghidra, implemented fully in Java but powered by Ghidra's APIs internally. This plugin allows users to communicate from/to radare2 instances via r2web and r2pipe protocols.

R4Ghidra supports not just the most common radare2 commands, but also all the handy command tricks you can do with r2 oneliners, including pipes, redirects, iterations, command substitution, file operations and more. The plugin features a complete REPL (Read-Eval-Print Loop) implementation that faithfully reproduces the radare2 command line experience within Ghidra.

Please use the [Issue tracker](https://github.com/radareorg/ghidra-r2web/issues) for feedback and bug reports!

![r4ghidra](doc/images/r4ghidra.png)


## Build

To build the plugin, simply run:

```bash
make
```

The extension .zip will be created in `dist/` directory. You can also download pre-built releases from the [release page](https://github.com/radareorg/ghidra-r2web/releases).

To install that extension just run `make install` and that will remove the current r4ghidra plugin in your detected Ghidra installation and place the last build into the ghidra Extensions directory. And you will only need to follow  these simple steps:

1. Run ./ghidraRun
2. In **Ghidra Project Manager** choose `File->Install Extensions`
3. Click on the R4Ghidra plugin, close the window
4. You will be prompted to restart ghidra. Do it
5. When loading the project it will prompt you to setup the R4Ghidra plugin
6. Click in `Tools->R4Ghidra` menu

### Debugging Issues

ghidraRun will start in background mode by default, you must edit the script to replace "bg" with "fg" to see backtraces and other startup debugging logs.

### Build Requirements

- Java21
- GHIDRA
- Gradle 8.x

### Ubuntu

```bash
sudo apt install openjdk-21-jdk:amd64
sudo snap install ghidra --edge
sudo snap install gradle --edge --classic
make
```

### IDEA

A Run Configuration is provided for IntelliJ IDEA. To make it work you should: 

* Run IDEA with the `GHIDRA_INSTALL_DIR` environment variable set to your Ghidra release (not source!) directory.
* Set the location of your Ghidra installation by adding the `GHIDRA_INSTALL_DIR` Path Variable under `File->Settings->Path Variables`.

If everything is set up correctly IDEA should recognize the Gradle project and load external dependencies referenced by the Run Configuration from the referenced Ghidra directory. If everything is right you should see that `Use classpath of module` is set to `-cp R4Ghidra.main` in the Run Configuration GUI, and no errors are shown. You'll get a `ClassNotFoundException` when trying to use the Run Configuration if external dependencies were not discovered as expected. 


## Installation

### Install

1. In **Ghidra Project Manager** choose `File->Install Extensions`
2. In the top right corner of the new window click the green plus sign
3. Choose the R4Ghidra distribution ZIP file from the `dist/` directory or downloaded from the release page
4. Restart Ghidra as instructed
5. After restart open the **Code Browser**, which should offer you to configure the new extension
6. Accept and tick the checkbox next to the plugin name

If the configuration option is not offered after restart, you can manually enable the plugin:
1. Use the `File->Configure` menu item
2. Click the Configure link under Ghidra Core
3. Find and enable the R4Ghidra plugin in the list

### Uninstall

1. In **Ghidra Project Manager** choose `File->Install Extensions`
2. Select R4Ghidra from the list of installed extensions
3. Click the red X button in the top right corner to uninstall
4. Restart Ghidra as instructed

## Usage

### GUI Mode

The plugin registers a new menu item under the Tools menu of Ghidra's Code Browser to start/stop the embedded web server. Once started, you can:

1. Use the built-in r2 REPL directly within Ghidra
2. Connect from an external radare2 instance using r2's web protocols

### Headless Mode

The Python script provided in the `ghidra_scripts` directory initializes the R4Ghidra server on port 9191 by default. You can change the port by setting the `R4GHIDRA_PORT` environment variable (or `R2WEB_PORT` for backward compatibility). You should provide this script as `-postScript` when launching headless Ghidra:

```bash
./support/analyzeHeadless /path/to/project-dir project-name \
  -process binary_name -postScript /path/to/r4ghidra_headless.py
```

Note: The older script name `r2web_headless.py` is still available for backward compatibility.

### R2 Features Support

R4Ghidra implements a complete radare2 REPL with support for:

- Common r2 commands (seek, print, analyze, info, etc.)
- Command syntax features (pipes, redirects, command substitution)
- Temporary addressing with @ syntax
- Multiple command execution with @@ syntax
- Shell command execution
- File operations (with sandboxing)
- Environment variables
- Output filtering with grep-like syntax
- Command output formatting (JSON, CSV, etc.)

For more detailed information about the REPL implementation and supported features, see the REPL documentation in the source code.
