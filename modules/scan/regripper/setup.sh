#!/usr/bin/env bash
# Build a local Perl environment for RegRipper 4.0 (Parse::Win32Registry).
set -euo pipefail

MODULE_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$MODULE_DIR/RegRipper4.0"
PERL_BASE="$MODULE_DIR/perl-lib"
PERL5LIB="$PERL_BASE/lib/perl5"
MARKER="$PERL_BASE/.setup-complete"

if [[ ! -d "$REPO_DIR" ]]; then
  echo "RegRipper repo not found at $REPO_DIR" >&2
  echo "Clone https://github.com/keydet89/RegRipper4.0 into that directory first." >&2
  exit 1
fi

patch_regripper_rip() {
  local rip="$REPO_DIR/rip.pl"
  if grep -q 'sub alertMsg' "$rip"; then
    return 0
  fi
  echo "Patching rip.pl with missing alertMsg() helper ..."
  perl -i -pe '
    if (/^sub parsePluginsFile/ && !$done) {
      $_ = "# Kirby patch: restore alertMsg() for TLN/alert plugins\nsub alertMsg {\n\t::rptMsg(\$_[0]);\n}\n\n" . $_;
      $done = 1;
    }
  ' "$rip"
}

if [[ -f "$MARKER" ]]; then
  patch_regripper_rip
  echo "RegRipper Perl environment already built ($PERL_BASE)"
  exit 0
fi

if ! command -v perl >/dev/null 2>&1; then
  echo "perl is required but was not found on PATH" >&2
  exit 1
fi

mkdir -p "$PERL_BASE"

echo "Installing Parse::Win32Registry into $PERL_BASE ..."
PERL_MM_OPT="INSTALL_BASE=$PERL_BASE" PERL5LIB="$PERL5LIB" PERL_MM_USE_DEFAULT=1 \
  cpan Parse::Win32Registry

perl -I"$PERL5LIB" -MParse::Win32Registry -e 'print "Parse::Win32Registry OK\n"'

patch_regripper_rip

touch "$MARKER"
echo "RegRipper Perl environment ready at $PERL_BASE"
