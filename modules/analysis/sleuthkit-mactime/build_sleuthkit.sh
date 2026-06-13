#!/usr/bin/env bash
# Build a local Sleuth Kit install for the sleuthkit-mactime analysis module.
#
# Prerequisites (Homebrew):
#   brew install autoconf automake libtool pkg-config
#
# Usage:
#   ./modules/analysis/sleuthkit-mactime/build_sleuthkit.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
SRC="${ROOT}/SleuthKit"
PREFIX="${ROOT}/install"

if [[ ! -d "${SRC}/.git" ]]; then
	echo "Sleuth Kit source not found at ${SRC}" >&2
	echo "Clone with: git clone https://github.com/sleuthkit/sleuthkit.git ${SRC}" >&2
	exit 1
fi

cd "${SRC}"

export PATH="/opt/homebrew/bin:/usr/local/bin:${PATH}"

# HEAD can fail to compile on macOS; pin a known-good release.
if [[ -z "$(git describe --tags --exact-match 2>/dev/null || true)" ]]; then
	git fetch --tags --depth 1 origin sleuthkit-4.15.0 2>/dev/null || true
	git checkout sleuthkit-4.15.0
fi

if [[ ! -f configure ]]; then
	./bootstrap
fi

if [[ ! -f Makefile ]] || [[ configure -nt Makefile ]]; then
	./configure --prefix="${PREFIX}"
fi

make -j"$(sysctl -n hw.ncpu 2>/dev/null || echo 2)"
make install

echo "Sleuth Kit installed to ${PREFIX}"
echo "  tsk_gettimes: ${PREFIX}/bin/tsk_gettimes"
echo "  mactime:      ${PREFIX}/bin/mactime"
