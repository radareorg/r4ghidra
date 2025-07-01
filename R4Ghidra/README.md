# R4Ghidra Plugin

This is the original `ghidra-r2web` script refactored into a Ghidra module. Implementation is mostly taken as-is in the hope that fixes will be easier in the new code structure, any feedback is appreciated. Please use the [Issue tracker](https://github.com/radareorg/ghidra-r2web/issues)!


## Build

SDKMan environment configuration is provided.

```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra
gradle buildExtension
```

The extension .zip will be created in `dist/`.

### Ubuntu

```bash
sudo snap install ghidra --edge
sudo snap install gradle --edge --classic
make
```

### IDEA

A Run Configuration is provided for IntelliJ IDEA. To make it work you should set the location of your Ghidra installation by adding the `GHIDRA_INSTALL_DIR` Path Variable under `File->Settings->Path Variables`.


## Install

In **Ghidra Project Manager** choose `File->Install Extensions`. In the top right corner of the new window click the green plus sign, and choose the distribution ZIP. Restart Ghidra as instructed.

After restart open the **Code Browser**, that should offer you to configure the new extension. Accept and tick the checkbox next to the plugin name. If this option is not offered you can use the `File->Configure` menu item, then click the Configure link under Ghidra Core to navigate to the same GUI for enabling the plugin.


## Usage

The plugin registers a new menu item under the Tools menu of Ghidra's Code Browser to start/stop the embedded web server. From there you can use r2's connection syntax as described in the original README. 

### Headless

The Python script provided in the `ghidra_scripts` directory initializes the R4Ghidra server on port 9191 by default. You can change the port by setting the `R4GHIDRA_PORT` environment variable (or `R2WEB_PORT` for backward compatibility). You should provide this script as `-postScript` when launching headless Ghidra:

```bash
./support/analyzeHeadless /path/to/project-dir project-name \
  -process binary_name -postScript /path/to/r4ghidra_headless.py
```

Note: The older script name `r2web_headless.py` is still available for backward compatibility.
