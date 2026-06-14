#!/usr/bin/env bash
# Wrapper — RegRipper rip.pl with the local Parse::Win32Registry environment.
set -euo pipefail

SOURCE="${BASH_SOURCE[0]:-$0}"
while [[ -L "$SOURCE" ]]; do
  DIR="$(cd "$(dirname "$SOURCE")" && pwd)"
  SOURCE="$(readlink "$SOURCE")"
  [[ "$SOURCE" != /* ]] && SOURCE="$DIR/$SOURCE"
done
ROOT="$(cd "$(dirname "$SOURCE")/.." && pwd)"
REGripper="${ROOT}/modules/scan/regripper/RegRipper4.0/rip.pl"
PERL5LIB_DIR="${ROOT}/modules/scan/regripper/perl-lib/lib/perl5"

if [[ ! -f "${REGripper}" ]]; then
    echo "RegRipper not found at ${REGripper}" >&2
    echo "Clone RegRipper4.0 into modules/scan/regripper/ and run modules/scan/regripper/setup.sh" >&2
    exit 1
fi

export PERL5LIB="${PERL5LIB_DIR}${PERL5LIB:+:${PERL5LIB}}"
exec perl "${REGripper}" "$@"
