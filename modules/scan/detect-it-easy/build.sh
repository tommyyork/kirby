#!/usr/bin/env bash
# Build diec (Detect It Easy console) from DIE-engine source.
# Run from the project root with the venv activated:
#   source .venv/bin/activate
#   ./modules/scan/detect-it-easy/build.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
MODULE_DIR="$ROOT/modules/scan/detect-it-easy"
DIE_REPO="$MODULE_DIR/Detect-it-easy"
ENGINE_REPO="$MODULE_DIR/DIE-engine"
BUILD_DIR="$ENGINE_REPO/build"

die() {
    echo "error: $*" >&2
    exit 1
}

if [[ ! -d "$DIE_REPO/.git" ]]; then
    die "Detect-it-easy repo not found at $DIE_REPO — clone it first"
fi

if [[ ! -d "$ENGINE_REPO/.git" ]]; then
    echo "Cloning DIE-engine..."
    git clone --recursive --depth 1 https://github.com/horsicq/DIE-engine.git "$ENGINE_REPO"
fi

if [[ ! -L "$ENGINE_REPO/Detect-It-Easy" && -d "$ENGINE_REPO/Detect-It-Easy" ]]; then
    rm -rf "$ENGINE_REPO/Detect-It-Easy"
fi
if [[ ! -e "$ENGINE_REPO/Detect-It-Easy" ]]; then
    ln -s ../Detect-it-easy "$ENGINE_REPO/Detect-It-Easy"
fi

QT6_QML_DIR="/opt/homebrew/opt/qtdeclarative/lib/cmake/Qt6Qml"
if [[ ! -f "$QT6_QML_DIR/Qt6QmlConfig.cmake" ]]; then
    die "Qt6 Qml not found — install with: brew install qtbase qtdeclarative"
fi

mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

cmake .. -DQt6Qml_DIR="$QT6_QML_DIR"
make -j"$(sysctl -n hw.ncpu 2>/dev/null || nproc)" diec

DIE_BIN="$BUILD_DIR/release/diec"
if [[ ! -x "$DIE_BIN" ]]; then
    die "Build finished but diec not found at $DIE_BIN"
fi

echo "Built diec: $DIE_BIN"
"$DIE_BIN" --version
echo ""
echo "To use this build, set diec in modules/scan/detect-it-easy/detect-it-easy.conf:"
echo "  diec = modules/scan/detect-it-easy/DIE-engine/build/release/diec"
