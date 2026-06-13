"""oletools module — run olevba against Office/OLE files from the file inventory."""

from __future__ import annotations

import configparser
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from kirby_flagged import record_flagged
from kirby_log import KirbyLogger
from kirby_report import format_scan_report_header

MODULE_DIR = Path(__file__).resolve().parent
TOOL_NAME = "oletools"

RETURN_OPEN_ERROR = 5
RETURN_ENCRYPTED = 9

OLEVBA_FLAG_PATTERNS = (
    (re.compile(r"\|\s*Suspicious\s*\|", re.IGNORECASE), "Suspicious"),
    (re.compile(r"\|\s*AutoExec\s*\|", re.IGNORECASE), "AutoExec"),
    (re.compile(r"\|\s*IOC\s*\|", re.IGNORECASE), "IOC"),
    (re.compile(r"\|\s*Hex\s*\|", re.IGNORECASE), "Hex"),
    (re.compile(r"\|\s*Base64\s*\|", re.IGNORECASE), "Base64"),
)
NO_MACROS_MESSAGE = re.compile(r"No VBA or XLM macros found\.", re.IGNORECASE)

OLE_HEADER = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
ZIP_HEADERS = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")

OPENXML_EXTENSIONS = {
    ".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm", ".dotm",
    ".xltm", ".xlam", ".potm", ".ppsm", ".vsdm",
}
OLE_EXTENSIONS = {
    ".doc", ".xls", ".ppt", ".dot", ".xlt", ".xla", ".pub", ".vsd", ".msi",
}
RTF_EXTENSIONS = {".rtf"}
SLK_EXTENSIONS = {".slk"}


def load_config(config_path: Path) -> configparser.ConfigParser:
    parser = configparser.ConfigParser()
    parser.read_string(f"[oletools]\n{config_path.read_text(encoding='utf-8')}")
    return parser


def project_path(config: configparser.ConfigParser, key: str) -> Path:
    value = config.get("oletools", key)
    path = Path(value)
    if path.is_absolute():
        return path
    return ROOT / path


def eligible_extensions(config: configparser.ConfigParser) -> set[str]:
    raw = config.get("oletools", "extensions")
    extensions: set[str] = set()
    for item in raw.split(","):
        ext = item.strip().lower()
        if not ext:
            continue
        if not ext.startswith("."):
            ext = f".{ext}"
        extensions.add(ext)
    if not extensions:
        raise RuntimeError("No extensions configured for oletools module")
    return extensions


def config_bool(config: configparser.ConfigParser, key: str, default: bool = True) -> bool:
    if not config.has_option("oletools", key):
        return default
    return config.getboolean("oletools", key, fallback=default)


def is_recycle_bin_sidecar(path: Path) -> bool:
    in_recycle_bin = any(part.lower() == "$recycle.bin" for part in path.parts)
    return in_recycle_bin and path.name.startswith("$I")


def read_file_header(path: Path, size: int = 512) -> bytes:
    with path.open("rb") as handle:
        return handle.read(size)


def has_zip_header(data: bytes) -> bool:
    return any(data.startswith(signature) for signature in ZIP_HEADERS)


def has_rtf_header(data: bytes) -> bool:
    stripped = data.lstrip()
    return stripped.startswith(b"{\\rtf") or stripped.startswith(b"{\\RTF")


def has_slk_header(data: bytes) -> bool:
    sample = data[:64].decode("latin-1", errors="ignore")
    return sample.startswith("ID;") or sample.startswith("P;") or "SYLK" in sample


def has_valid_office_header(path: Path) -> bool:
    header = read_file_header(path)
    ext = path.suffix.lower()

    if ext in OPENXML_EXTENSIONS:
        return has_zip_header(header)
    if ext in OLE_EXTENSIONS:
        return header.startswith(OLE_HEADER)
    if ext in RTF_EXTENSIONS:
        return has_rtf_header(header)
    if ext in SLK_EXTENSIONS:
        return has_slk_header(header)

    return (
        header.startswith(OLE_HEADER)
        or has_zip_header(header)
        or has_rtf_header(header)
        or has_slk_header(header)
    )


def read_file_list(path: Path, log: KirbyLogger) -> list[Path]:
    if not path.is_file():
        raise FileNotFoundError(f"File list not found: {path}")

    log.step(f"Reading file inventory from {path}")
    files: list[Path] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        entry = line.strip()
        if entry:
            files.append(Path(entry))
    log.step(f"Loaded {len(files)} paths from inventory")
    return files


def filter_eligible_files(
    files: list[Path],
    extensions: set[str],
    config: configparser.ConfigParser,
    log: KirbyLogger,
) -> list[Path]:
    exclude_sidecars = config_bool(config, "exclude_recycle_bin_sidecars", default=True)
    validate_headers = config_bool(config, "validate_file_headers", default=True)

    log.step(f"Filtering for extensions: {', '.join(sorted(extensions))}")
    if exclude_sidecars:
        log.step("Excluding Recycle Bin $I* sidecar files")
    if validate_headers:
        log.step("Validating Office/OLE file headers")

    eligible: list[Path] = []
    skipped_sidecars = 0
    skipped_headers = 0

    for path in log.progress(files, total=len(files), desc="Filtering files", unit="file"):
        if not path.is_file() or path.suffix.lower() not in extensions:
            continue
        if exclude_sidecars and is_recycle_bin_sidecar(path):
            skipped_sidecars += 1
            continue
        if validate_headers and not has_valid_office_header(path):
            skipped_headers += 1
            continue
        eligible.append(path)

    eligible.sort(key=lambda path: str(path).lower())
    log.step(f"Found {len(eligible)} eligible Office/OLE files")
    if exclude_sidecars and skipped_sidecars:
        log.step(f"Skipped {skipped_sidecars} Recycle Bin $I* sidecar file(s)")
    if validate_headers and skipped_headers:
        log.step(f"Skipped {skipped_headers} file(s) with invalid headers")
    return eligible


def find_olevba(log: KirbyLogger) -> list[str]:
    venv_olevba = ROOT / ".venv" / "bin" / "olevba"
    if venv_olevba.is_file():
        log.step(f"Using olevba from {venv_olevba}")
        return [str(venv_olevba)]

    found = shutil.which("olevba")
    if found:
        log.step(f"Using olevba from PATH: {found}")
        return [found]

    log.step(f"Using olevba via {sys.executable} -m oletools.olevba")
    return [sys.executable, "-m", "oletools.olevba"]


def run_olevba(command: list[str], filepath: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [*command, str(filepath)],
        capture_output=True,
        text=True,
        check=False,
    )


def is_olevba_flagged(result: subprocess.CompletedProcess[str]) -> bool:
    output = f"{result.stdout or ''}\n{result.stderr or ''}"
    return any(pattern.search(output) for pattern, _ in OLEVBA_FLAG_PATTERNS)


def has_vba_or_xlm_macros(result: subprocess.CompletedProcess[str]) -> bool:
    output = f"{result.stdout or ''}\n{result.stderr or ''}"
    return not NO_MACROS_MESSAGE.search(output)


def should_include_in_report(result: subprocess.CompletedProcess[str]) -> bool:
    if result.returncode == RETURN_OPEN_ERROR:
        return False
    return has_vba_or_xlm_macros(result)


def should_flag_file(result: subprocess.CompletedProcess[str]) -> bool:
    if result.returncode == RETURN_OPEN_ERROR:
        return False
    if result.returncode == RETURN_ENCRYPTED:
        return True
    return is_olevba_flagged(result)


def flag_summary(result: subprocess.CompletedProcess[str]) -> str:
    if result.returncode == RETURN_ENCRYPTED:
        return "encrypted document"
    output = f"{result.stdout or ''}\n{result.stderr or ''}"
    hits = [label for pattern, label in OLEVBA_FLAG_PATTERNS if pattern.search(output)]
    if hits:
        return ", ".join(hits)
    return "suspicious macro indicators"


def format_file_section(filepath: Path, result: subprocess.CompletedProcess[str]) -> str:
    lines = [f"### `{filepath}`", ""]

    output = (result.stdout or "").strip()
    errors = (result.stderr or "").strip()

    if output:
        lines.extend(["```", output, "```"])
    else:
        lines.append("_No output._")

    if errors:
        lines.extend(["", "**stderr:**", "", "```", errors, "```"])

    if result.returncode not in (0, 1):
        lines.extend(["", f"_olevba exited with code {result.returncode}_"])

    lines.append("")
    return "\n".join(lines)


def format_report(
    target: Path,
    config: configparser.ConfigParser,
    sections: list[str],
) -> str:
    lines = format_scan_report_header(
        "# oletools Scan Report",
        target,
        config,
        "oletools",
    )

    if sections:
        lines.extend(["## Results", ""])
        lines.extend(sections)
    else:
        lines.extend(["## Results", "", "No eligible Office/OLE files found."])

    return "\n".join(lines)


def run(
    target: Path,
    output: Path,
    config: Path,
    *,
    verbose: bool = True,
    flagged_csv: Path | None = None,
    file_list: Path | None = None,
) -> None:
    log = KirbyLogger(verbose, prefix="oletools")
    log.step(f"Loading config from {config}")
    settings = load_config(config)
    file_list_path = file_list or project_path(settings, "file_list")
    flagged_csv_path = flagged_csv or file_list_path.parent / "flagged.csv"
    extensions = eligible_extensions(settings)

    all_files = read_file_list(file_list_path, log)
    eligible_files = filter_eligible_files(all_files, extensions, settings, log)
    olevba_cmd = find_olevba(log)

    sections: list[str] = []
    flagged_paths: list[Path] = []
    for filepath in log.progress(
        eligible_files,
        total=len(eligible_files),
        desc="Running olevba",
        unit="file",
    ):
        result = run_olevba(olevba_cmd, filepath)
        if should_include_in_report(result):
            sections.append(format_file_section(filepath, result))
        if should_flag_file(result):
            log.flag(f"{filepath} — {flag_summary(result)}")
            flagged_paths.append(filepath)

    if flagged_paths:
        updated = record_flagged(flagged_paths, TOOL_NAME, csv_path=flagged_csv_path)
        log.step(f"Updated {updated} path(s) in {flagged_csv_path}")

    if sections:
        log.step(f"Writing report to {output}")
        report = format_report(
            target=target,
            config=settings,
            sections=sections,
        )
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(report, encoding="utf-8")
    else:
        log.step("No VBA or XLM macros found; skipping report")
        if output.is_file():
            output.unlink()
