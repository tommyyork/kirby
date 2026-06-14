#!/usr/bin/env bash
# Create the project virtual environment and hook .venv/bin/activate to venv-paths.sh.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
VENV_DIR="${ROOT}/.venv"
ACTIVATE="${VENV_DIR}/bin/activate"
PYTHON="${VENV_DIR}/bin/python"
HOOK_MARKER="venv-paths.sh"

chmod +x "${ROOT}/bin/"*.pl 2>/dev/null || true

if [[ ! -d "${VENV_DIR}" ]]; then
    echo "Creating virtual environment at ${VENV_DIR} ..."
    python3 -m venv --upgrade-deps "${VENV_DIR}"
else
    echo "Using existing virtual environment at ${VENV_DIR}"
fi

if [[ ! -f "${ACTIVATE}" ]] || [[ ! -x "${PYTHON}" ]]; then
    echo "Virtual environment is incomplete: ${VENV_DIR}" >&2
    exit 1
fi

if ! grep -q "${HOOK_MARKER}" "${ACTIVATE}"; then
    cat >> "${ACTIVATE}" << 'EOF'

# Kirby project paths (venv-paths.sh)
if [ -f "${VIRTUAL_ENV}/../venv-paths.sh" ]; then
    . "${VIRTUAL_ENV}/../venv-paths.sh"
fi
EOF
    echo "Hooked ${ACTIVATE} to source venv-paths.sh"
else
    echo "Activate hook already present (${HOOK_MARKER})"
fi

install_venv_tool_links() {
    local tool target link tools
    tools="$(grep '^KIRBY_VENV_TOOLS=' "${ROOT}/venv-paths.sh" 2>/dev/null | head -1 | sed 's/^KIRBY_VENV_TOOLS=//; s/"//g')"
    for tool in ${tools:-rip.pl rr.pl}; do
        target="${ROOT}/bin/${tool}"
        link="${VENV_DIR}/bin/${tool}"
        if [[ ! -x "${target}" ]]; then
            echo "Warning: missing wrapper ${target}; skipping ${link}" >&2
            continue
        fi
        ln -sf "../../bin/${tool}" "${link}"
    done
}

install_venv_tool_links
echo "Linked RegRipper tools into ${VENV_DIR}/bin/"

repair_pip() {
    if "${PYTHON}" -m pip --version &>/dev/null; then
        return 0
    fi

    echo "Repairing broken pip installation ..."
    local site_packages
    site_packages="$(find "${VENV_DIR}/lib" -type d -name site-packages -print -quit)"
    if [[ -n "${site_packages}" ]]; then
        rm -rf \
            "${site_packages}/pip" \
            "${site_packages}"/pip-*.dist-info \
            "${site_packages}"/~ip-*.dist-info
    fi
    "${PYTHON}" -m ensurepip --upgrade
}

install_python_deps() {
    repair_pip
    echo "Installing Python dependencies ..."
    if ! "${PYTHON}" -m pip install --upgrade pip; then
        echo "Warning: pip self-upgrade failed; continuing with installed pip." >&2
    fi
    "${PYTHON}" -m pip install -r "${ROOT}/requirements.txt"
}

if ! install_python_deps; then
    echo "Error: pip install failed." >&2
    exit 1
fi

echo "Done. Activate with: source .venv/bin/activate"
echo "RegRipper tools (rip.pl, rr.pl) are on PATH via ${ROOT}/bin/ and ${VENV_DIR}/bin/"
