#!/usr/bin/env python3
"""Test HTTP commands against a real Ghidra program without opening the GUI."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--ghidra", default=os.environ.get("GHIDRA_INSTALL_DIR"))
args = parser.parse_args()
if not args.ghidra:
    parser.error("set GHIDRA_INSTALL_DIR or pass --ghidra with a Ghidra installation")


def java_tool(name):
    home = os.environ.get("JAVA_HOME")
    return str(Path(home) / "bin" / name) if home else shutil.which(name)


with tempfile.TemporaryDirectory(prefix="r4ghidra-http-") as directory:
    work = Path(directory)
    jars = list((Path(args.ghidra) / "Ghidra").rglob("*.jar"))
    jars += list((ROOT / "R4Ghidra/lib").glob("*.jar"))
    classpath = os.pathsep.join(map(str, [work, *jars]))
    sources = list((ROOT / "R4Ghidra/src/main/java").rglob("*.java"))
    sources.append(ROOT / "R4Ghidra/src/test/java/r4ghidra/R4GhidraHttpHandlerTest.java")
    subprocess.run([java_tool("javac"), "-cp", classpath, "-d", work, *sources],
                   check=True, cwd=ROOT)
    subprocess.run([java_tool("java"), "-Djava.awt.headless=true",
                    f"-Duser.home={work / 'home'}", "-cp", classpath,
                    "r4ghidra.R4GhidraHttpHandlerTest", args.ghidra], check=True, cwd=ROOT)
