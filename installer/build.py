#!/usr/bin/env python3
"""
Build Hostblock.setup.exe - the Windows installer (setup wizard) for HostBlock.

    python3 installer/build.py

What it does
  1. Downloads a private Python runtime for Windows. Versions are pinned and
     every file is checked against a SHA-256 hash before it is used:
       - Python 3.14.10 from NuGet (the official package, published by the
         Python Software Foundation)
       - Tkinter with Tcl/Tk 8.6 from conda-forge (the NuGet package leaves
         them out, but the HostBlock window needs them)
  2. Assembles installer/build/runtime/ (unneeded parts like pip are left out).
  3. Runs NSIS on installer/HostBlock.nsi -> dist/Hostblock.setup.exe

Requirements
  - Python 3.8+
  - NSIS 3 that can build 64-bit installers ("makensis" with amd64-unicode stubs and plugins):
        Debian/Ubuntu, also inside WSL on Windows:  sudo apt install nsis zstd
        anywhere else: NSIS built from source with  scons TARGET_ARCH=amd64
    The official NSIS download and Homebrew's makensis only ship 32-bit stubs, so they
    can't build this installer; build.py checks this before downloading anything.
  - zstd support: Python 3.14+, the "zstandard" package, or the zstd command
"""

from __future__ import annotations

import hashlib
import io
import re
import shutil
import subprocess
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
BUILD = HERE / "build"
DOWNLOADS = BUILD / "downloads"
RUNTIME = BUILD / "runtime"
DIST = ROOT / "dist"
OUTFILE = DIST / "Hostblock.setup.exe"

PY_NUGET = {
    "file": "python.3.14.10.nupkg",
    "url": "https://api.nuget.org/v3-flatcontainer/python/3.14.10/python.3.14.10.nupkg",
    "sha256": "f54ba67c9951c3d773ea47d2bb095150c037c399f0423a968bcda22809241784",
}
PY_CONDA = {  # only _tkinter.pyd and Lib/tkinter are taken from this one
    "file": "python-3.14.10-h53f6dd8_100_cp314.conda",
    "url": "https://conda.anaconda.org/conda-forge/win-64/python-3.14.10-h53f6dd8_100_cp314.conda",
    "sha256": "c9f74f58f15bcd7571869903e43fa1e1bc3b60d9faf959f71979415f360a8281",
}
TK_CONDA = {
    "file": "tk-8.6.13-h967ab96_4.conda",
    "url": "https://conda.anaconda.org/conda-forge/win-64/tk-8.6.13-h967ab96_4.conda",
    "sha256": "f19618a3a82cc483dacf1c70a30367ee7b0c7e71b90f1f80e14feff44fbd3688",
}

# Parts of the NuGet Python that HostBlock never uses.
# tcl8.6/tzdata and tcl8.6/msgs only serve Tcl's "clock" command, which Tkinter never uses;
# together they are ~45% of the runtime's files, so leaving them out makes setup much faster.
PRUNE = ["include", "libs", "Lib/ensurepip", "Lib/venv", "Lib/idlelib", "Lib/turtledemo",
         "Lib/test", "Lib/pydoc_data", "Lib/site-packages/pip", "tcl/tcl8.6/tzdata", "tcl/tcl8.6/msgs"]


def log(msg: str) -> None:
    print(f"[build] {msg}", flush=True)


def fetch(src: dict) -> bytes:
    """Download (or reuse a cached copy of) a pinned file and verify its SHA-256."""
    DOWNLOADS.mkdir(parents=True, exist_ok=True)
    path = DOWNLOADS / src["file"]
    if path.exists() and hashlib.sha256(path.read_bytes()).hexdigest() == src["sha256"]:
        log(f"cached   {src['file']}")
        return path.read_bytes()
    log(f"download {src['url']}")
    request = urllib.request.Request(src["url"], headers={"User-Agent": "hostblock-build"})
    with urllib.request.urlopen(request, timeout=120) as resp:
        data = resp.read()
    digest = hashlib.sha256(data).hexdigest()
    if digest != src["sha256"]:
        sys.exit(f"SHA-256 mismatch for {src['file']}:\n  expected {src['sha256']}\n  got      {digest}")
    path.write_bytes(data)
    return data


def zstd_decompress(data: bytes) -> bytes:
    try:
        from compression import zstd  # Python 3.14+
        return zstd.decompress(data)
    except ImportError:
        pass
    try:
        import zstandard
        return zstandard.ZstdDecompressor().decompressobj().decompress(data)
    except ImportError:
        pass
    exe = shutil.which("zstd")
    if exe:
        return subprocess.run([exe, "-dc"], input=data, stdout=subprocess.PIPE, check=True).stdout
    sys.exit("zstd support is needed: use Python 3.14+, 'pip install zstandard', or install the zstd tool.")


def conda_extract(data: bytes, dest: Path, part: str = "pkg") -> None:
    """Extract the pkg-*.tar.zst (or info-*.tar.zst) member of a .conda package."""
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        name = next(n for n in z.namelist() if n.startswith(f"{part}-") and n.endswith(".tar.zst"))
        tar_bytes = zstd_decompress(z.read(name))
    with tarfile.open(fileobj=io.BytesIO(tar_bytes)) as tar:
        if hasattr(tarfile, "data_filter"):
            tar.extractall(dest, filter="data")
        else:
            for member in tar.getmembers():
                if member.name.startswith(("/", "\\")) or ".." in Path(member.name).parts:
                    sys.exit(f"unsafe path in package: {member.name}")
            tar.extractall(dest)


def copytree(src: Path, dst: Path) -> None:
    shutil.copytree(src, dst, dirs_exist_ok=True, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))


def build_runtime() -> None:
    if RUNTIME.exists():
        shutil.rmtree(RUNTIME)
    work = BUILD / "extract"
    if work.exists():
        shutil.rmtree(work)

    log("assembling Python runtime")
    with zipfile.ZipFile(io.BytesIO(fetch(PY_NUGET))) as z:
        z.extractall(work / "nuget")
    copytree(work / "nuget" / "tools", RUNTIME)

    log("adding Tkinter and Tcl/Tk 8.6")
    conda_extract(fetch(PY_CONDA), work / "py")
    tk_data = fetch(TK_CONDA)
    conda_extract(tk_data, work / "tk")
    conda_extract(tk_data, work / "tk-info", part="info")

    shutil.copy2(work / "py" / "DLLs" / "_tkinter.pyd", RUNTIME / "DLLs")
    copytree(work / "py" / "Lib" / "tkinter", RUNTIME / "Lib" / "tkinter")
    for dll in ("tcl86t.dll", "tk86t.dll", "zlib1.dll"):   # next to _tkinter.pyd, as in python.org builds
        shutil.copy2(work / "tk" / "Library" / "bin" / dll, RUNTIME / "DLLs")
    for lib in ("tcl8.6", "tk8.6"):                     # <prefix>\tcl\..., as in python.org builds
        copytree(work / "tk" / "Library" / "lib" / lib, RUNTIME / "tcl" / lib)
    licenses = sorted((work / "tk-info" / "info" / "licenses").rglob("*"))
    for i, lic in enumerate(p for p in licenses if p.is_file()):
        shutil.copy2(lic, RUNTIME / "tcl" / ("LICENSE-TclTk.txt" if i == 0 else f"LICENSE-TclTk-{i}.txt"))
    shutil.rmtree(work)

    for rel in PRUNE:
        target = RUNTIME / rel
        if target.is_dir():
            shutil.rmtree(target)
    for leftover in [*(RUNTIME / "Lib" / "site-packages").glob("pip-*.dist-info"), *RUNTIME.rglob("__pycache__")]:
        shutil.rmtree(leftover, ignore_errors=True)

    files = sum(1 for p in RUNTIME.rglob("*") if p.is_file())
    size = sum(p.stat().st_size for p in RUNTIME.rglob("*") if p.is_file())
    log(f"runtime ready: {RUNTIME} ({files} files, {size / 1_048_576:.1f} MB)")


def app_version() -> str:
    match = re.search(r'^VERSION = "([\d.]+)"', (ROOT / "hostblock.py").read_text(encoding="utf-8"), re.M)
    if not match:
        sys.exit("could not read VERSION from hostblock.py")
    return match.group(1)


def find_makensis() -> str:
    """Check that makensis exists and can build 64-bit installers, before the long download."""
    makensis = shutil.which("makensis")
    if not makensis:
        sys.exit("makensis (NSIS 3) was not found on PATH - see the requirements at the top of this file.")
    BUILD.mkdir(parents=True, exist_ok=True)
    probe = BUILD / "probe.nsi"
    probe.write_text('Unicode true\nTarget amd64-unicode\nOutFile "probe.exe"\n'
                     "Section\n  nsExec::Exec 'cmd /c exit 0'\nSectionEnd\n", encoding="utf-8")
    result = subprocess.run([makensis, "-V1", str(probe)], cwd=BUILD,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    probe.unlink()
    (BUILD / "probe.exe").unlink(missing_ok=True)
    if result.returncode != 0:
        sys.exit("This NSIS can't build 64-bit installers (no amd64-unicode stubs/plugins).\n"
                 "Use the Debian/Ubuntu 'nsis' package (also works in WSL), or NSIS built with "
                 "'scons TARGET_ARCH=amd64'.\n\n" + result.stdout.strip())
    return makensis


def build_installer(makensis: str) -> None:
    DIST.mkdir(exist_ok=True)
    version = app_version()
    log(f"running NSIS for HostBlock {version}")
    subprocess.run([makensis, "-V2", "-WX", "-INPUTCHARSET", "UTF8",  # -WX: warnings are errors
                    f"-DVERSION={version}", f"-DROOT={ROOT}", f"-DRUNTIME={RUNTIME}",
                    f"-DOUTFILE={OUTFILE}", str(HERE / "HostBlock.nsi")], check=True)
    digest = hashlib.sha256(OUTFILE.read_bytes()).hexdigest()
    log(f"done: {OUTFILE} ({OUTFILE.stat().st_size / 1_048_576:.1f} MB)")
    log(f"SHA-256: {digest}")


if __name__ == "__main__":
    nsis = find_makensis()
    if "--installer-only" not in sys.argv or not RUNTIME.exists():
        build_runtime()
    build_installer(nsis)
