# Third-party notices

HostBlock's own code is released under the [MIT License](LICENSE).

The source code in this repository has no third-party dependencies. The Windows installer,
`Hostblock.setup.exe`, does bundle third-party components. Each keeps its own license, and the
license texts are installed alongside them in `C:\Program Files\HostBlock\runtime\`.

| Component | Version | Source | License | License text in the install |
|---|---|---|---|---|
| Python, for Windows (x64) | 3.14.10 | Official [`python` NuGet package](https://www.nuget.org/packages/python/3.14.10), Python Software Foundation | [PSF License v2](https://docs.python.org/3/license.html) | `runtime\LICENSE.txt` |
| Tkinter (`_tkinter.pyd`, `Lib\tkinter`) | 3.14.10 | [conda-forge `python`](https://anaconda.org/conda-forge/python) package | PSF License v2 | `runtime\LICENSE.txt` |
| Tcl/Tk (`tcl86t.dll`, `tk86t.dll`, script libraries) | 8.6.13 | [conda-forge `tk`](https://anaconda.org/conda-forge/tk) package | [Tcl/Tk License](https://www.tcl.tk/software/tcltk/license.html) (BSD-style) | `runtime\tcl\LICENSE-TclTk.txt` |
| zlib (`zlib1.dll`, used by Tcl) | 1.x | conda-forge `tk` package | [zlib License](https://zlib.net/zlib_license.html) | listed here |
| Microsoft Visual C++ runtime (`vcruntime140*.dll`) | | Included with Python | Microsoft Distributable Code | `runtime\LICENSE.txt` ("Additional Conditions for this Windows binary build") |

Python's `LICENSE.txt` also covers the libraries that the Python Windows build includes, such as
bzip2, libffi, OpenSSL, SQLite, mpdecimal, expat and Zstandard.

The installer is built with [NSIS](https://nsis.sourceforge.io), whose own license is the
[zlib/libpng license](https://nsis.sourceforge.io/License). Its LZMA compressor uses the CPL with
the NSIS exception.

## Blocklist data

The domain lists aren't bundled. HostBlock downloads them when it runs, from
[StevenBlack/hosts](https://github.com/StevenBlack/hosts) (MIT License), which merges lists from
several sources, each under its own license. See that project's README for details.

## zlib License

```
Copyright (C) 1995-2024 Jean-loup Gailly and Mark Adler

This software is provided 'as-is', without any express or implied
warranty.  In no event will the authors be held liable for any damages
arising from the use of this software.

Permission is granted to anyone to use this software for any purpose,
including commercial applications, and to alter it and redistribute it
freely, subject to the following restrictions:

1. The origin of this software must not be misrepresented; you must not
   claim that you wrote the original software. If you use this software
   in a product, an acknowledgment in the product documentation would be
   appreciated but is not required.
2. Altered source versions must be plainly marked as such, and must not be
   misrepresented as being the original software.
3. This notice may not be removed or altered from any source distribution.
```
