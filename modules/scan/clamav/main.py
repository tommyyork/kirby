"""ClamAV scan module — run clamdscan against the scan target via a local clamd."""

from __future__ import annotations

import configparser
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from kirby_flagged import record_flagged
from kirby_kext import is_kext_target, kext_search_roots
from kirby_file_list import read_scan_paths, uses_explicit_file_list
from kirby_log import KirbyLogger
from kirby_report import format_scan_report_header, scan_timestamp

MODULE_DIR = Path(__file__).resolve().parent
RUN_DIR = MODULE_DIR / "run"
TOOL_NAME = "clamav"
SCAN_BATCH_SIZE = 250

FOUND_PATTERN = re.compile(
    r"^(?P<path>.+?):\s+(?P<signature>.+?)\s+FOUND\s*$",
)


@dataclass(frozen=True)
class ClamDetection:
    path: Path
    signature: str


def load_config(config_path: Path) -> configparser.ConfigParser:
    parser = configparser.ConfigParser()
    parser.read_string(f"[clamav]\n{config_path.read_text(encoding='utf-8')}")
    return parser


def project_path(config: configparser.ConfigParser, key: str) -> Path:
    value = config.get("clamav", key)
    path = Path(value)
    if path.is_absolute():
        return path
    return ROOT / path


def module_path(config: configparser.ConfigParser, key: str) -> Path:
    value = config.get("clamav", key)
    path = Path(value)
    if path.is_absolute():
        return path
    return MODULE_DIR / path


def find_executable(name: str, log: KirbyLogger) -> str:
    path = shutil.which(name)
    if path:
        log.step(f"Using {name} from {path}")
        return path

    for candidate in (
        Path("/opt/homebrew/bin") / name,
        Path("/usr/local/bin") / name,
    ):
        if candidate.is_file():
            log.step(f"Using {name} from {candidate}")
            return str(candidate)

    raise RuntimeError(f"{name} not found on PATH (install with: brew install clamav)")


def verify_database(database: Path, log: KirbyLogger) -> None:
    if not database.is_dir():
        raise RuntimeError(
            f"ClamAV database directory not found: {database}\n"
            "Update signatures with: freshclam"
        )

    signatures = list(database.glob("*.cvd")) + list(database.glob("*.cld"))
    if not signatures:
        raise RuntimeError(
            f"No ClamAV signature databases found in {database}\n"
            "Update signatures with: freshclam"
        )
    log.step(f"Using ClamAV database at {database} ({len(signatures)} signature file(s))")


def clamd_conf_path(config: configparser.ConfigParser) -> Path:
    return module_path(config, "clamd_config")


def resolve_clamd_config(source: Path, database: Path) -> Path:
    """Write a runtime clamd config with an absolute DatabaseDirectory from clamav.conf."""
    RUN_DIR.mkdir(parents=True, exist_ok=True)
    resolved = RUN_DIR / "clamd.conf"
    lines: list[str] = []
    replaced = False

    for line in source.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            lines.append(line)
            continue
        if stripped.startswith("DatabaseDirectory "):
            lines.append(f"DatabaseDirectory {database}")
            replaced = True
        else:
            lines.append(line)

    if not replaced:
        lines.insert(0, f"DatabaseDirectory {database}")

    resolved.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    return resolved


def ensure_clamd(clamdscan: str, clamd: str, clamd_conf: Path, log: KirbyLogger) -> None:
    RUN_DIR.mkdir(parents=True, exist_ok=True)

    ping = subprocess.run(
        [clamdscan, f"--config-file={clamd_conf}", "--ping=1"],
        capture_output=True,
        text=True,
        check=False,
    )
    if ping.returncode == 0:
        log.step("clamd is already running for Kirby configuration")
        return

    log.step(f"Starting clamd with {clamd_conf}")
    subprocess.Popen(
        [clamd, f"--config-file={clamd_conf}"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )

    wait = subprocess.run(
        [clamdscan, f"--config-file={clamd_conf}", "--wait", "--ping=30"],
        capture_output=True,
        text=True,
        check=False,
    )
    if wait.returncode != 0:
        detail = (wait.stderr or wait.stdout or "").strip()
        raise RuntimeError(
            f"clamd did not become ready (exit {wait.returncode})"
            + (f": {detail}" if detail else "")
        )
    log.step("clamd is ready")


def scan_targets(target: Path, *, include_kext: bool = False) -> list[Path]:
    if is_kext_target(target):
        return [path.resolve(strict=False) for path in kext_search_roots()]

    roots = [target.resolve(strict=False)]
    if include_kext:
        roots.extend(path.resolve(strict=False) for path in kext_search_roots())
    return roots


def read_file_list(path: Path, log: KirbyLogger) -> list[Path]:
    if not path.is_file():
        raise FileNotFoundError(f"File list not found: {path}")

    log.step(f"Reading file inventory from {path}")
    files = [Path(entry.strip()) for entry in path.read_text(encoding="utf-8").splitlines() if entry.strip()]
    log.step(f"Loaded {len(files)} paths from inventory")
    return files


def is_under_root(path: Path, root: Path) -> bool:
    try:
        resolved_path = path.resolve(strict=False)
        resolved_root = root.resolve(strict=False)
        if resolved_root.is_file():
            return resolved_path == resolved_root
        return resolved_path == resolved_root or resolved_path.is_relative_to(resolved_root)
    except (OSError, ValueError):
        return False


def is_under_any_root(path: Path, roots: list[Path]) -> bool:
    return any(is_under_root(path, root) for root in roots)


def walk_root_files(root: Path) -> list[Path]:
    if root.is_file():
        return [root.resolve(strict=False)]

    if not root.is_dir():
        return []

    files = [path for path in root.rglob("*") if path.is_file()]
    files.sort(key=lambda item: str(item).lower())
    return files


def collect_scan_files(
    scan_roots: list[Path],
    *,
    target: Path,
    file_list: Path | None,
    log: KirbyLogger,
) -> list[Path]:
    if uses_explicit_file_list(target, file_list):
        files = [path for path in read_scan_paths(target, log) if path.is_file()]
        files.sort(key=lambda item: str(item).lower())
        log.step(f"Selected {len(files)} file(s) from explicit file list")
        return files

    if file_list is not None and file_list.is_file():
        files = [
            path
            for path in read_file_list(file_list, log)
            if path.is_file() and is_under_any_root(path, scan_roots)
        ]
        files.sort(key=lambda item: str(item).lower())
        log.step(f"Selected {len(files)} file(s) from inventory for scanning")
        return files

    files: list[Path] = []
    seen: set[str] = set()
    for root in scan_roots:
        for path in walk_root_files(root):
            key = str(path.resolve(strict=False)).lower()
            if key in seen:
                continue
            seen.add(key)
            files.append(path)

    files.sort(key=lambda item: str(item).lower())
    log.step(f"Collected {len(files)} file(s) for scanning")
    return files


def parse_detections(text: str) -> list[ClamDetection]:
    detections: list[ClamDetection] = []
    seen: set[tuple[str, str]] = set()

    for line in text.splitlines():
        match = FOUND_PATTERN.match(line.strip())
        if not match:
            continue
        path = Path(match.group("path").strip())
        signature = match.group("signature").strip()
        key = (str(path), signature)
        if key in seen:
            continue
        seen.add(key)
        detections.append(ClamDetection(path=path, signature=signature))

    return detections


def append_clamdscan_log(log_path: Path, text: str) -> None:
    if not text.strip():
        return

    with log_path.open("a", encoding="utf-8") as handle:
        if log_path.stat().st_size > 0:
            handle.write("\n")
        handle.write(text.strip() + "\n")


def run_clamdscan_batch(
    clamdscan: str,
    clamd_conf: Path,
    files: list[Path],
) -> tuple[list[ClamDetection], str, int]:
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="utf-8") as handle:
        for path in files:
            handle.write(f"{path}\n")
        file_list_path = Path(handle.name)

    try:
        command = [
            clamdscan,
            "--fdpass",
            "--infected",
            f"--config-file={clamd_conf}",
            f"--file-list={file_list_path}",
        ]
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
        )
    finally:
        file_list_path.unlink(missing_ok=True)

    combined_output = "\n".join(
        part.strip()
        for part in (result.stdout, result.stderr)
        if part and part.strip()
    )
    detections = parse_detections(combined_output)

    if result.returncode not in (0, 1):
        detail = combined_output or f"exit code {result.returncode}"
        raise RuntimeError(f"clamdscan failed for batch of {len(files)} file(s): {detail}")

    return detections, combined_output, result.returncode


def run_clamdscan_on_files(
    clamdscan: str,
    clamd_conf: Path,
    files: list[Path],
    clamdscan_log: Path,
    log: KirbyLogger,
) -> list[ClamDetection]:
    if not files:
        log.step("No files to scan")
        return []

    detections: list[ClamDetection] = []
    seen_paths: set[str] = set()
    batch: list[Path] = []

    def process_batch(current_batch: list[Path]) -> None:
        batch_detections, output, _code = run_clamdscan_batch(
            clamdscan,
            clamd_conf,
            current_batch,
        )
        append_clamdscan_log(clamdscan_log, output)
        for detection in batch_detections:
            path_key = str(detection.path)
            if path_key in seen_paths:
                continue
            seen_paths.add(path_key)
            detections.append(detection)
            log.flag(f"{detection.path} — {detection.signature}")

    for filepath in log.progress(
        files,
        total=len(files),
        desc="Scanning files",
        unit="file",
    ):
        batch.append(filepath)
        if len(batch) < SCAN_BATCH_SIZE:
            continue
        process_batch(batch)
        batch = []

    if batch:
        process_batch(batch)

    if detections:
        log.step(f"clamdscan reported {len(detections)} detection(s)")
    else:
        log.step("clamdscan found no detections")

    return detections


def format_report(
    target: Path,
    config: configparser.ConfigParser,
    *,
    detections: list[ClamDetection],
    clamdscan_log: Path,
    clamd_conf: Path,
    database: Path,
    scan_roots: list[Path],
    clamdscan_version: str,
    scan_time: str,
) -> str:
    lines = format_scan_report_header(
        "# ClamAV Scan Report",
        target,
        config,
        "clamav",
        scan_time=scan_time,
    )
    lines.extend(
        [
            f"- **clamdscan version:** {clamdscan_version}",
            f"- **clamd config:** `{clamd_conf}`",
            f"- **Database directory:** `{database}`",
            f"- **Scan log:** `{clamdscan_log}`",
            "",
        ]
    )

    if len(scan_roots) > 1:
        lines.extend(["## Scan roots", ""])
        for root in scan_roots:
            lines.append(f"- `{root}`")
        lines.append("")

    if detections:
        lines.extend(
            [
                f"## Detections ({len(detections)})",
                "",
                "| File | Signature |",
                "| --- | --- |",
            ]
        )
        for detection in sorted(detections, key=lambda item: str(item.path)):
            lines.append(f"| `{detection.path}` | `{detection.signature}` |")
    else:
        lines.extend(["## Detections", "", "No detections found.", ""])

    lines.append("")
    return "\n".join(lines)


def clamdscan_version(clamdscan: str) -> str:
    result = subprocess.run(
        [clamdscan, "--version"],
        capture_output=True,
        text=True,
        check=False,
    )
    return (result.stdout or result.stderr).strip() or "unknown"


def run(
    target: Path,
    output: Path,
    config: Path,
    *,
    verbose: bool = True,
    flagged_csv: Path | None = None,
    file_list: Path | None = None,
    include_kext: bool = False,
    force_errors: bool = False,
) -> None:
    log = KirbyLogger(verbose, prefix="clamav")
    log.step(f"Loading config from {config}")
    settings = load_config(config)

    flagged_csv_path = flagged_csv or (
        file_list.parent / "flagged.csv" if file_list is not None else ROOT / "tmp" / "flagged.csv"
    )
    database = project_path(settings, "database")
    clamd_conf_source = clamd_conf_path(settings)
    if not clamd_conf_source.is_file():
        raise FileNotFoundError(f"clamd config not found: {clamd_conf_source}")
    clamd_conf = resolve_clamd_config(clamd_conf_source, database)

    clamdscan_bin = find_executable("clamdscan", log)
    clamd_bin = find_executable("clamd", log)
    verify_database(database, log)

    clamdscan_log = output.parent / "clamdscan.log"
    clamdscan_log.parent.mkdir(parents=True, exist_ok=True)
    if clamdscan_log.is_file():
        clamdscan_log.write_text("", encoding="utf-8")

    ensure_clamd(clamdscan_bin, clamd_bin, clamd_conf, log)

    scan_roots = scan_targets(target, include_kext=include_kext)
    scan_files = collect_scan_files(
        scan_roots,
        target=target,
        file_list=file_list,
        log=log,
    )
    all_detections = run_clamdscan_on_files(
        clamdscan_bin,
        clamd_conf,
        scan_files,
        clamdscan_log,
        log,
    )

    flagged_paths = [detection.path for detection in all_detections]
    if flagged_paths:
        updated = record_flagged(flagged_paths, TOOL_NAME, csv_path=flagged_csv_path)
        log.step(f"Updated {updated} path(s) in {flagged_csv_path}")

    scan_time = scan_timestamp()
    report = format_report(
        target=target,
        config=settings,
        detections=all_detections,
        clamdscan_log=clamdscan_log,
        clamd_conf=clamd_conf,
        database=database,
        scan_roots=scan_roots,
        clamdscan_version=clamdscan_version(clamdscan_bin),
        scan_time=scan_time,
    )

    log.step(f"Writing report to {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(report, encoding="utf-8")
