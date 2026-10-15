#!/usr/bin/env python3
"""Test the native codec, optionally against a Ghidra installation and a recent radare2."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--ghidra", default=os.environ.get("GHIDRA_INSTALL_DIR"))
parser.add_argument("--r2", default=os.environ.get("R2_BIN"))
args = parser.parse_args()


def java_tool(name):
    home = os.environ.get("JAVA_HOME")
    return str(Path(home) / "bin" / name) if home else shutil.which(name)


def run(command, **kwargs):
    return subprocess.run(list(map(str, command)), check=True, cwd=ROOT, **kwargs)


def verify_native(path, address, comment, noreturn):
    command = f"prj load {path};fj;CCj;aflj;axlj"
    result = run([args.r2, "-N", "-q", "-c", command, "malloc://0x3000"],
                 capture_output=True, text=True)
    flags, comments, functions, refs = map(json.loads, result.stdout.splitlines())
    assert any(f["name"] == "test.flag" and f["addr"] == address + 0x10 for f in flags)
    assert any(c["offset"] == address + 0x14 and c["name"] == comment for c in comments)
    assert any(f["name"] == "test.func" and f["addr"] == address + 0x20
               and f["size"] == 8 and f["noreturn"] == noreturn for f in functions)
    assert any(r["from"] == address + 0x20 and r["addr"] == address + 0x10 for r in refs)
    print("radare2 restored flags, comments, function blocks and references")


with tempfile.TemporaryDirectory(prefix="r4ghidra-project-") as directory:
    work = Path(directory)
    main = ROOT / "R4Ghidra/src/main/java"
    tests = ROOT / "R4Ghidra/src/test/java"
    sources = [main / "r4ghidra/project/R2Project.java",
               main / "r4ghidra/project/R2ProjectCodec.java",
               tests / "r4ghidra/project/R2ProjectCodecTest.java"]
    jars = []
    if args.ghidra:
        jars = list((Path(args.ghidra) / "Ghidra").rglob("*.jar"))
        jars += list((ROOT / "R4Ghidra/lib").glob("*.jar"))
        sources = list(main.rglob("*.java")) + list(tests.rglob("*.java"))
    classpath = os.pathsep.join(map(str, [work, *jars]))
    run([java_tool("javac"), "-cp", classpath, "-d", work, *sources])
    codec = [java_tool("java"), "-cp", classpath, "r4ghidra.project.R2ProjectCodecTest"]
    if args.r2:
        native = work / "native.rprj"
        rewritten = work / "java.rprj"
        command = ("f test.flag 4 @ 0x10;CCu native comment @ 0x14;af+ 0x20 test.func;"
                   f"afb+ 0x20 0x20 8;axd 0x10 0x20;prj save {native}")
        run([args.r2, "-N", "-q", "-c", command, "malloc://256"])
        run([*codec, native, rewritten])
        verify_native(rewritten, 0, "native comment", False)
    else:
        run(codec)
    if args.ghidra:
        exported = work / "ghidra.rprj"
        run([java_tool("java"), "-Djava.awt.headless=true", f"-Duser.home={work / 'home'}",
             "-cp", classpath, "r4ghidra.project.R2ProjectIntegrationTest", args.ghidra, exported,
             *([native] if args.r2 else [])])
        if args.r2:
            verify_native(exported, 0x2000, "imported comment", True)
