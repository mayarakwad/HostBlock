#!/bin/sh
# macOS: double-click this file in Finder to open the HostBlock window.
cd "$(dirname "$0")" || exit 1
exec python3 HostBlock.pyw
