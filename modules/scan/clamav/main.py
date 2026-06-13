"""ClamAV scan module — run clamdscan against the scan target via a local clamd."""

from __future__ import annotations

import configparser
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from kirby_flagged import record_flagged
from kirby_kext import is_kext_target, kext_search_roots
from kirby_log import KirbyLogger
from kirby_report import format_scan_report_header, scan_timestamp

MODULE_DIR = Path(__file__).resolve().parent
RUN_DIR = MODULE_DIR / "run"
TOOL_NAME = "ClamAV"

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


def scan_targets(target: Path) -> list[Path]:
    if is_kext_target(target):
        return [path.resolve(strict=False) for path in kext_search_roots()]
    return [target.resolve(strict=False)]


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


def run_clamdscan(
    clamdscan: str,
    clamd_conf: Path,
    scan_path: Path,
    log_path: Path,
    log: KirbyLogger,
) -> tuple[list[ClamDetection], str, int]:
    log.step(f"Running clamdscan on {scan_path}")
    command = [
        clamdscan,
        "--fdpass",
        f"--log={log_path}",
        f"--config-file={clamd_conf}",
        str(scan_path),
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
    )

    combined_output = "\n".join(
        part.strip()
        for part in (result.stdout, result.stderr)
        if part and part.strip()
    )

    log_text = ""
    if log_path.is_file():
        log_text = log_path.read_text(encoding="utf-8", errors="replace")

    detections = parse_detections(combined_output)
    seen = {(str(item.path), item.signature) for item in detections}
    if log_text:
        for detection in parse_detections(log_text):
            key = (str(detection.path), detection.signature)
            if key not in seen:
                seen.add(key)
                detections.append(detection)

    if result.returncode not in (0, 1):
        detail = combined_output or log_text.strip() or f"exit code {result.returncode}"
        raise RuntimeError(f"clamdscan failed for {scan_path}: {detail}")

    if result.returncode == 1:
        log.step(f"clamdscan reported {len(detections)} detection(s) under {scan_path}")
    else:
        log.step(f"clamdscan found no detections under {scan_path}")

    return detections, combined_output, result.returncode


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

    scan_roots = scan_targets(target)
    all_detections: list[ClamDetection] = []
    seen_paths: set[str] = set()

    for scan_path in scan_roots:
        detections, _output, _code = run_clamdscan(
            clamdscan_bin,
            clamd_conf,
            scan_path,
            clamdscan_log,
            log,
        )
        for detection in detections:
            path_key = str(detection.path)
            if path_key in seen_paths:
                continue
            seen_paths.add(path_key)
            all_detections.append(detection)
            log.flag(f"{detection.path} — {detection.signature}")

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
