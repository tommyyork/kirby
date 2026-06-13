#!/usr/bin/env bash
# Build a local Perl environment for RegRipper (Parse::Win32Registry + patched modules).
set -euo pipefail

MODULE_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$MODULE_DIR/RegRipper3.0"
PERL_BASE="$MODULE_DIR/perl-lib"
PERL5LIB="$PERL_BASE/lib/perl5"
PATCH_DEST="$PERL5LIB/Parse/Win32Registry/WinNT"
MARKER="$PERL_BASE/.setup-complete"

if [[ ! -d "$REPO_DIR" ]]; then
  echo "RegRipper repo not found at $REPO_DIR" >&2
  echo "Clone https://github.com/keydet89/RegRipper3.0 into that directory first." >&2
  exit 1
fi

if [[ -f "$MARKER" ]]; then
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

echo "Applying RegRipper-patched Win32Registry modules ..."
chmod u+w "$PATCH_DEST/Base.pm" "$PATCH_DEST/File.pm" "$PATCH_DEST/Key.pm" 2>/dev/null || true
cp "$REPO_DIR/Base.pm" "$PATCH_DEST/Base.pm"
cp "$REPO_DIR/File.pm" "$PATCH_DEST/File.pm"
cp "$REPO_DIR/Key.pm" "$PATCH_DEST/Key.pm"

perl -I"$PERL5LIB" -MParse::Win32Registry -e 'print "Parse::Win32Registry OK\n"'

touch "$MARKER"
echo "RegRipper Perl environment ready at $PERL_BASE"
