# Kirby venv path extensions — sourced from .venv/bin/activate after creation.
#
# Adds project bin/ wrappers (rip.pl, rr.pl, …) to PATH so RegRipper tools are
# available when the virtual environment is active.

KIRBY_VENV_TOOLS="rip.pl rr.pl"

if [ -z "${VIRTUAL_ENV:-}" ]; then
    return 0 2>/dev/null || exit 0
fi

KIRBY_ROOT="$(cd "${VIRTUAL_ENV}/.." && pwd)"
export KIRBY_ROOT

_kirby_bin="${KIRBY_ROOT}/bin"
if [ -d "${_kirby_bin}" ]; then
    case ":${PATH}:" in
        *:"${_kirby_bin}":*) ;;
        *)
            PATH="${_kirby_bin}:${PATH}"
            export PATH
            ;;
    esac
fi

unset _kirby_bin
