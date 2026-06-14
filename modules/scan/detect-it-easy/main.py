"""detect-it-easy module — run diec against executable-like files from the inventory."""

from __future__ import annotations

import configparser
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from kirby_file_list import read_scan_paths, uses_explicit_file_list
from kirby_flagged import record_flagged
from kirby_log import KirbyLogger
from kirby_report import format_scan_report_header
from kirby_tool_errors import check_subprocess

MODULE_DIR = Path(__file__).resolve().parent
TOOL_NAME = "detect-it-easy"


def load_config(config_path: Path) -> configparser.ConfigParser:
    parser = configparser.ConfigParser()
    parser.read_string(f"[detect-it-easy]\n{config_path.read_text(encoding='utf-8')}")
    return parser


def project_path(config: configparser.ConfigParser, key: str) -> Path:
    value = config.get("detect-it-easy", key)
    path = Path(value)
    if path.is_absolute():
        return path
    return ROOT / path


MACOS_BUNDLE_MACOS_DIR = "/Contents/MacOS/"


def eligible_extensions(config: configparser.ConfigParser) -> set[str]:
    raw = config.get("detect-it-easy", "extensions")
    extensions: set[str] = set()
    for item in raw.split(","):
        ext = item.strip().lower()
        if not ext:
            continue
        if not ext.startswith("."):
            ext = f".{ext}"
        extensions.add(ext)
    if not extensions:
        raise RuntimeError("No extensions configured for detect-it-easy module")
    return extensions


def flag_types(config: configparser.ConfigParser) -> set[str]:
    raw = config.get("detect-it-easy", "flag_types")
    types = {item.strip().lower() for item in raw.split(",") if item.strip()}
    if not types:
        raise RuntimeError("No flag_types configured for detect-it-easy module")
    return types


def optional_config_csv_set(config: configparser.ConfigParser, key: str) -> set[str]:
    """Parse an optional comma-separated config value; empty or missing means no entries."""
    if not config.has_option("detect-it-easy", key):
        return set()
    raw = config.get("detect-it-easy", key, fallback="")
    if raw is None:
        return set()
    return {item.strip() for item in str(raw).split(",") if item.strip()}


def config_bool(config: configparser.ConfigParser, key: str, default: bool = False) -> bool:
    if not config.has_option("detect-it-easy", key):
        return default
    return config.getboolean("detect-it-easy", key, fallback=default)


def is_macos_bundle_executable(path: Path) -> bool:
    """Extension-less Mach-O binary inside a macOS bundle MacOS folder."""
    return path.is_file() and not path.suffix and MACOS_BUNDLE_MACOS_DIR in path.as_posix()


def is_eligible_file(path: Path, extensions: set[str], *, scan_macos_binaries: bool) -> bool:
    if not path.is_file():
        return False
    if path.suffix.lower() in extensions:
        return True
    if scan_macos_binaries and is_macos_bundle_executable(path):
        return True
    return False


def read_file_list(path: Path, log: KirbyLogger) -> list[Path]:
    if not path.is_file():
        raise FileNotFoundError(f"File list not found: {path}")

    return read_scan_paths(path, log)


def filter_eligible_files(
    files: list[Path],
    extensions: set[str],
    log: KirbyLogger,
    *,
    scan_macos_binaries: bool,
) -> list[Path]:
    log.step(f"Filtering for extensions: {', '.join(sorted(extensions))}")
    if scan_macos_binaries:
        log.step(
            "Including extension-less Mach-O binaries under "
            f"{MACOS_BUNDLE_MACOS_DIR.rstrip('/')}"
        )

    eligible: list[Path] = []
    macos_bundle_count = 0
    for path in log.progress(files, total=len(files), desc="Filtering files", unit="file"):
        if not is_eligible_file(path, extensions, scan_macos_binaries=scan_macos_binaries):
            continue
        eligible.append(path)
        if scan_macos_binaries and is_macos_bundle_executable(path):
            macos_bundle_count += 1

    eligible.sort(key=lambda path: str(path).lower())
    log.step(f"Found {len(eligible)} eligible files")
    if scan_macos_binaries and macos_bundle_count:
        log.step(f"Included {macos_bundle_count} macOS bundle executable(s)")
    return eligible


def ensure_diec(path: Path, log: KirbyLogger) -> Path:
    if not path.is_file():
        raise FileNotFoundError(
            f"diec not found at {path}. Build it with: ./modules/scan/detect-it-easy/build.sh"
        )
    if not path.stat().st_mode & 0o111:
        raise RuntimeError(f"diec is not executable: {path}")
    log.step(f"Using diec from {path}")
    return path


def build_diec_command(
    diec: Path,
    config: configparser.ConfigParser,
    filepath: Path,
) -> list[str]:
    command = [
        str(diec),
        "-D",
        str(project_path(config, "database")),
        "-E",
        str(project_path(config, "extra_database")),
        "-C",
        str(project_path(config, "custom_database")),
        "-j",
    ]

    if config_bool(config, "hide_unknown", default=True):
        command.append("-U")
    if config_bool(config, "heuristic_scan", default=True):
        command.append("-u")
    if config_bool(config, "deep_scan", default=False):
        command.append("-d")
    if config_bool(config, "aggressive_scan", default=False):
        command.append("-g")

    command.append(str(filepath))
    return command


def run_diec(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
    )


def normalize_detection_type(raw_type: str) -> str:
    return raw_type.lstrip("~").lower()


def is_heuristic_detection(row: dict[str, str]) -> bool:
    return row.get("type", "").startswith("~")


def has_authenticode_signature(detections: list[dict[str, str]]) -> bool:
    for row in detections:
        if row.get("type", "").lower() != "sign tool":
            continue
        haystack = f"{row.get('name', '')} {row.get('string', '')}".lower()
        if "authenticode" in haystack:
            return True
    return False


def parse_diec_json(stdout: str) -> dict | None:
    text = stdout.strip()
    if not text:
        return None

    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end < start:
        return None

    try:
        return json.loads(text[start : end + 1])
    except json.JSONDecodeError:
        return None


def collect_detections(payload: dict | None) -> list[dict[str, str]]:
    if not payload:
        return []

    rows: list[dict[str, str]] = []
    for detect in payload.get("detects", []):
        filetype = str(detect.get("filetype", ""))
        for value in detect.get("values", []):
            rows.append(
                {
                    "filetype": filetype,
                    "name": str(value.get("name", "")),
                    "type": str(value.get("type", "")),
                    "string": str(value.get("string", "")),
                    "version": str(value.get("version", "")),
                    "info": str(value.get("info", "")),
                }
            )
    return rows


def suspicious_detections(
    detections: list[dict[str, str]],
    flagged_types: set[str],
    *,
    ignore_names: set[str],
    ignore_heuristic_names: set[str],
    require_non_heuristic: bool,
    skip_authenticode_heuristic_only: bool,
) -> list[dict[str, str]]:
    hits: list[dict[str, str]] = []
    for row in detections:
        if normalize_detection_type(row.get("type", "")) not in flagged_types:
            continue
        name = row.get("name", "")
        if name in ignore_names:
            continue
        if is_heuristic_detection(row) and name in ignore_heuristic_names:
            continue
        hits.append(row)

    if not hits:
        return []

    if require_non_heuristic:
        has_signature_hit = any(not is_heuristic_detection(row) for row in hits)
        if not has_signature_hit:
            return []

    if skip_authenticode_heuristic_only:
        heuristic_only = all(is_heuristic_detection(row) for row in hits)
        if heuristic_only and has_authenticode_signature(detections):
            return []

    return hits


def format_detection_table(detections: list[dict[str, str]]) -> list[str]:
    lines = [
        "| Type | Name | Detection |",
        "| --- | --- | --- |",
    ]
    for row in detections:
        label = row.get("string") or row.get("name")
        lines.append(
            f"| `{row.get('type', '')}` | `{row.get('name', '')}` | {label} |"
        )
    return lines


def format_file_section(
    filepath: Path,
    filetype: str,
    detections: list[dict[str, str]],
    result: subprocess.CompletedProcess[str],
) -> str:
    lines = [f"### `{filepath}`", ""]
    if filetype:
        lines.append(f"- **Detected format:** `{filetype}`")
        lines.append("")

    lines.append("**Suspicious detections:**")
    lines.append("")
    lines.extend(format_detection_table(detections))
    lines.append("")

    stderr = (result.stderr or "").strip()
    if stderr:
        lines.extend(["**stderr:**", "", "```", stderr, "```", ""])

    lines.append(f"_diec exited with code {result.returncode}_")
    lines.append("")
    return "\n".join(lines)


def format_report(
    target: Path,
    config: configparser.ConfigParser,
    sections: list[str],
    scanned_count: int,
) -> str:
    lines = format_scan_report_header(
        "# Detect It Easy Scan Report",
        target,
        config,
        "detect-it-easy",
    )
    lines.append(f"- **Files scanned:** {scanned_count}")
    lines.append("")

    if sections:
        lines.extend(["## Suspicious Results", ""])
        lines.extend(sections)
    else:
        lines.extend(["## Results", "", "No suspicious packer/protector detections found."])

    return "\n".join(lines)


def run(
    target: Path,
    output: Path,
    config: Path,
    *,
    verbose: bool = True,
    flagged_csv: Path | None = None,
    file_list: Path | None = None,
    force_errors: bool = False,
) -> None:
    log = KirbyLogger(verbose, prefix="detect-it-easy")
    log.step(f"Loading config from {config}")
    settings = load_config(config)

    file_list_path = file_list or project_path(settings, "file_list")
    flagged_csv_path = flagged_csv or file_list_path.parent / "flagged.csv"
    extensions = eligible_extensions(settings)
    flagged_types = flag_types(settings)
    ignore_names = optional_config_csv_set(settings, "ignore_names")
    ignore_heuristic_names = optional_config_csv_set(settings, "ignore_heuristic_names")
    require_non_heuristic = config_bool(settings, "require_non_heuristic", default=True)
    skip_authenticode_heuristic_only = config_bool(
        settings,
        "skip_authenticode_heuristic_only",
        default=True,
    )
    diec_path = ensure_diec(project_path(settings, "diec"), log)

    scan_macos_binaries = config_bool(settings, "scan_macos_binaries", default=True)

    if uses_explicit_file_list(target, file_list_path):
        all_files = read_file_list(target, log)
    else:
        all_files = read_file_list(file_list_path, log)
    eligible_files = filter_eligible_files(
        all_files,
        extensions,
        log,
        scan_macos_binaries=scan_macos_binaries,
    )
    log.step(f"Flagging on detection types: {', '.join(sorted(flagged_types))}")
    if require_non_heuristic:
        log.step("Requiring at least one non-heuristic detection")
    if ignore_names:
        log.step("Ignoring detection names: " + ", ".join(sorted(ignore_names)))
    else:
        log.step("Not ignoring any detection names")
    if ignore_heuristic_names:
        log.step(
            "Ignoring heuristic names: "
            + ", ".join(sorted(ignore_heuristic_names))
        )
    else:
        log.step("Not ignoring any heuristic detection names")
    if skip_authenticode_heuristic_only:
        log.step("Skipping heuristic-only hits on Authenticode-signed files")

    sections: list[str] = []
    flagged_paths: list[Path] = []

    for filepath in log.progress(
        eligible_files,
        total=len(eligible_files),
        desc="Running diec",
        unit="file",
    ):
        command = build_diec_command(diec_path, settings, filepath)
        result = run_diec(command)
        if not check_subprocess(
            result,
            context=f"diec failed for {filepath}",
            allowed_returncodes=frozenset({0}),
            force_errors=force_errors,
        ):
            continue

        payload = parse_diec_json(result.stdout)
        detections = collect_detections(payload)
        hits = suspicious_detections(
            detections,
            flagged_types,
            ignore_names=ignore_names,
            ignore_heuristic_names=ignore_heuristic_names,
            require_non_heuristic=require_non_heuristic,
            skip_authenticode_heuristic_only=skip_authenticode_heuristic_only,
        )
        if not hits:
            continue

        filetype = ""
        if payload and payload.get("detects"):
            filetype = str(payload["detects"][0].get("filetype", ""))

        labels = ", ".join(
            (row.get("string") or row.get("name") or row.get("type", "")).strip()
            for row in hits[:3]
        )
        if len(hits) > 3:
            labels += f", +{len(hits) - 3} more"
        log.flag(f"{filepath} — {labels}")
        sections.append(format_file_section(filepath, filetype, hits, result))
        flagged_paths.append(filepath)

    if flagged_paths:
        updated = record_flagged(flagged_paths, TOOL_NAME, csv_path=flagged_csv_path)
        log.step(f"Updated {updated} path(s) in {flagged_csv_path}")
        log.step(f"Found {len(flagged_paths)} suspicious file(s)")
    else:
        log.step("No suspicious files detected")

    log.step(f"Writing report to {output}")
    report = format_report(
        target=target,
        config=settings,
        sections=sections,
        scanned_count=len(eligible_files),
    )

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(report, encoding="utf-8")
