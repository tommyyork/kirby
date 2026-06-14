"""sleuthkit-ntfs module — NTFS filesystem-level analysis via Sleuth Kit."""

from __future__ import annotations

import configparser
import hashlib
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from kirby_index import resolve_mount_point
from kirby_log import KirbyLogger
from kirby_sleuthkit import (
    find_tool,
    load_sleuthkit_settings,
    resolve_analysis_target,
    run_tsk_command,
    tsk_requires_sudo,
)
from kirby_target import is_disk_image_or_device, is_regular_file_target

MODULE_DIR = Path(__file__).resolve().parent
MODULE_SECTION = "sleuthkit-ntfs"
MARKER_PREFIX = "<!-- sleuthkit-ntfs:"

TIMESTAMP_PATTERN = re.compile(
    r"(?:File Modified|Modified|Created|Accessed|MFT Modified):\s*"
    r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})",
    re.IGNORECASE,
)
FLS_LINE = re.compile(
    r"^[rld]\/[rld]\s+\*\s+\d+-\d+-\d+:\s+(.+)$",
    re.IGNORECASE,
)


class TargetScope(str, Enum):
    VOLUME = "volume"
    DIRECTORY = "directory"
    FILE = "file"


class Severity(str, Enum):
    INFO = "info"
    SUSPECT = "suspect"
    ALERT = "alert"


@dataclass(frozen=True)
class Finding:
    severity: Severity
    category: str
    detail: str


@dataclass
class AnalysisResult:
    target: Path
    scope: TargetScope
    device: Path | None
    device_source: str | None
    mount_point: Path | None
    ntfs_path: str | None
    inode: int | None
    findings: list[Finding] = field(default_factory=list)
    raw_sections: dict[str, str] = field(default_factory=dict)

    def fingerprint(self) -> str:
        payload = {
            "scope": self.scope.value,
            "target": str(self.target),
            "device": str(self.device) if self.device else "",
            "ntfs_path": self.ntfs_path or "",
            "inode": self.inode,
            "findings": [
                (item.severity.value, item.category, item.detail)
                for item in sorted(
                    self.findings,
                    key=lambda f: (f.category, f.detail, f.severity.value),
                )
            ],
        }
        digest = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        return digest[:16]


def load_config(config_path: Path) -> configparser.ConfigParser:
    parser = configparser.ConfigParser()
    parser.read_string(f"[{MODULE_SECTION}]\n{config_path.read_text(encoding='utf-8')}")
    return parser


def project_path(config: configparser.ConfigParser, key: str) -> Path:
    value = config.get(MODULE_SECTION, key)
    path = Path(value)
    if path.is_absolute():
        return path
    return ROOT / path


def config_list(config: configparser.ConfigParser, key: str) -> list[str]:
    raw = config.get(MODULE_SECTION, key, fallback="")
    return [item.strip() for item in raw.split(",") if item.strip()]


def config_int(config: configparser.ConfigParser, key: str, default: int) -> int:
    if not config.has_option(MODULE_SECTION, key):
        return default
    return config.getint(MODULE_SECTION, key, fallback=default)


def config_bool(config: configparser.ConfigParser, key: str, default: bool = False) -> bool:
    if not config.has_option(MODULE_SECTION, key):
        return default
    return config.getboolean(MODULE_SECTION, key, fallback=default)


def is_mount_root(target: Path) -> bool:
    try:
        return target.resolve(strict=False) == resolve_mount_point(target).resolve(strict=False)
    except OSError:
        return False


def classify_target(target: Path) -> TargetScope:
    if is_disk_image_or_device(target):
        return TargetScope.VOLUME
    if is_regular_file_target(target):
        return TargetScope.FILE
    if target.is_dir() and is_mount_root(target):
        return TargetScope.VOLUME
    return TargetScope.DIRECTORY


def ntfs_path_for_target(target: Path, mount_point: Path) -> str:
    resolved_target = target.resolve(strict=False)
    resolved_mount = mount_point.resolve(strict=False)
    try:
        relative = resolved_target.relative_to(resolved_mount)
    except ValueError as exc:
        raise RuntimeError(
            f"Target `{target}` is not under mount point `{mount_point}`."
        ) from exc
    return "/" + relative.as_posix()


def parse_timestamp(value: str) -> datetime | None:
    try:
        return datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


def attribute_blocks(istat_output: str) -> list[tuple[str, str]]:
    blocks: list[tuple[str, str]] = []
    current_type = ""
    current_lines: list[str] = []
    for line in istat_output.splitlines():
        if line.startswith("Type: "):
            if current_type:
                blocks.append((current_type, "\n".join(current_lines)))
            current_type = line.split(":", 1)[1].strip()
            current_lines = [line]
        elif current_type:
            current_lines.append(line)
    if current_type:
        blocks.append((current_type, "\n".join(current_lines)))
    return blocks


def timestamps_from_block(block: str) -> dict[str, datetime]:
    timestamps: dict[str, datetime] = {}
    for match in TIMESTAMP_PATTERN.finditer(block):
        label_start = block.rfind("\n", 0, match.start()) + 1
        label_line = block[label_start : match.start()].strip().rstrip(":")
        label = label_line.split()[-1] if label_line else "Modified"
        parsed = parse_timestamp(match.group(1))
        if parsed is not None:
            timestamps[label] = parsed
    return timestamps


def analyze_istat_output(istat_output: str, threshold_seconds: int) -> list[Finding]:
    findings: list[Finding] = []
    lowered = istat_output.casefold()

    if "reparse point" in lowered or "$symbolic_link" in lowered:
        findings.append(
            Finding(
                Severity.INFO,
                "reparse_point",
                "MFT entry is a reparse point or symbolic link.",
            )
        )

    if "hidden" in lowered and "file" in lowered:
        findings.append(
            Finding(
                Severity.SUSPECT,
                "hidden_file",
                "MFT entry is marked hidden.",
            )
        )

    data_attributes = [block for kind, block in attribute_blocks(istat_output) if "$DATA" in kind]
    if len(data_attributes) > 1:
        findings.append(
            Finding(
                Severity.SUSPECT,
                "alternate_data_stream",
                f"MFT entry has {len(data_attributes)} $DATA attribute(s); possible ADS.",
            )
        )

    si_times: dict[str, datetime] = {}
    fn_times: dict[str, datetime] = {}
    for kind, block in attribute_blocks(istat_output):
        if "$STANDARD_INFORMATION" in kind:
            si_times = timestamps_from_block(block)
        if "$FILE_NAME" in kind:
            fn_times = timestamps_from_block(block)

    si_modified = si_times.get("Modified") or si_times.get("File")
    fn_modified = fn_times.get("Modified") or fn_times.get("File")
    if si_modified and fn_modified:
        delta = abs((si_modified - fn_modified).total_seconds())
        if delta >= threshold_seconds:
            findings.append(
                Finding(
                    Severity.ALERT,
                    "timestomp",
                    (
                        f"$STANDARD_INFORMATION modified ({si_modified}) differs from "
                        f"$FILE_NAME modified ({fn_modified}) by {int(delta)} seconds."
                    ),
                )
            )

    if "not allocated" in lowered:
        findings.append(
            Finding(
                Severity.SUSPECT,
                "unallocated_mft",
                "MFT entry is marked not allocated.",
            )
        )

    return findings


def tsk_base_args(resolved) -> list[str]:
    args = ["-f", "ntfs"]
    if resolved.bitlocker and resolved.password:
        args.extend(["-k", resolved.password])
    if resolved.image_offset is not None:
        args.extend(["-o", str(resolved.image_offset)])
    return args


def resolve_ntfs_image(target, settings, config, log):
    scope = classify_target(target)
    prefer_config = config_bool(config, "prefer_config_device", default=False)

    if scope is TargetScope.VOLUME:
        resolved = resolve_analysis_target(
            target,
            settings,
            log,
            prefer_config_device=prefer_config,
        )
        return resolved, target if target.is_dir() else None

    mount_point = resolve_mount_point(target)
    if is_disk_image_or_device(mount_point):
        return resolve_analysis_target(
            mount_point,
            settings,
            log,
            prefer_config_device=prefer_config,
        ), mount_point

    if prefer_config:
        return resolve_analysis_target(
            mount_point,
            settings,
            log,
            prefer_config_device=True,
        ), mount_point

    return resolve_analysis_target(mount_point, settings, log), mount_point


def ensure_ntfs_filesystem(output: str) -> None:
    text = output.strip()
    if not text:
        raise RuntimeError("fsstat produced no output; unable to verify NTFS filesystem")
    lowered = text.casefold()
    if "not a ntfs" in lowered or "invalid magic value" in lowered:
        raise RuntimeError(f"Target is not an NTFS filesystem: {text}")


def run_mmls(mmls_cmd, resolved, log):
    command = [mmls_cmd, str(resolved.device)]
    result = run_tsk_command(
        command,
        log,
        privileged=tsk_requires_sudo(resolved.device),
    )
    output = "\n".join(part for part in (result.stdout, result.stderr) if part).strip()
    if result.returncode != 0 and not output:
        raise RuntimeError(f"mmls failed with exit code {result.returncode}")
    return output


def run_fsstat(fsstat_cmd, resolved, log):
    command = [fsstat_cmd, *tsk_base_args(resolved), str(resolved.device)]
    result = run_tsk_command(
        command,
        log,
        privileged=tsk_requires_sudo(resolved.device),
    )
    output = "\n".join(part for part in (result.stdout, result.stderr) if part).strip()
    if result.returncode != 0 and not output:
        raise RuntimeError(f"fsstat failed with exit code {result.returncode}")
    ensure_ntfs_filesystem(output)
    if result.returncode != 0:
        raise RuntimeError(f"fsstat failed: {output}")
    return output


def run_fls(fls_cmd, resolved, ntfs_path, log):
    command = [
        fls_cmd,
        *tsk_base_args(resolved),
        "-p",
        ntfs_path.strip("/"),
        str(resolved.device),
    ]
    result = run_tsk_command(
        command,
        log,
        privileged=tsk_requires_sudo(resolved.device),
    )
    output = "\n".join(part for part in (result.stdout, result.stderr) if part).strip()
    if result.returncode != 0 and not output:
        raise RuntimeError(
            f"fls failed for `{ntfs_path}` with exit code {result.returncode}"
        )
    return output


def run_ifind(ifind_cmd, resolved, ntfs_path, log):
    command = [
        ifind_cmd,
        *tsk_base_args(resolved),
        str(resolved.device),
        "-n",
        ntfs_path,
    ]
    result = run_tsk_command(
        command,
        log,
        privileged=tsk_requires_sudo(resolved.device),
    )
    output = (result.stdout or "").strip().splitlines()
    if result.returncode != 0 or not output:
        return None
    try:
        return int(output[-1].strip())
    except ValueError:
        return None


def run_istat(istat_cmd, resolved, inode, log):
    command = [istat_cmd, *tsk_base_args(resolved), str(resolved.device), str(inode)]
    result = run_tsk_command(
        command,
        log,
        privileged=tsk_requires_sudo(resolved.device),
    )
    output = "\n".join(part for part in (result.stdout, result.stderr) if part).strip()
    if result.returncode != 0 and not output:
        raise RuntimeError(f"istat failed for inode {inode} with exit code {result.returncode}")
    return output


def fls_path_findings(fls_output, *, suspicious_patterns, executable_extensions):
    findings: list[Finding] = []
    seen_paths: set[str] = set()

    for line in fls_output.splitlines():
        match = FLS_LINE.match(line.strip())
        if not match:
            continue
        path = match.group(1).replace("\\", "/")
        if path in seen_paths:
            continue
        seen_paths.add(path)

        path_lower = path.casefold()
        suffix = Path(path).suffix.casefold()
        for pattern in suspicious_patterns:
            if pattern.casefold() in path_lower and suffix in executable_extensions:
                findings.append(
                    Finding(
                        Severity.SUSPECT,
                        "suspicious_path",
                        f"Executable `{path}` under suspicious location `{pattern}`.",
                    )
                )
                break

    return findings


def analyze_volume(target, resolved, config, tools, log):
    result = AnalysisResult(
        target=target,
        scope=TargetScope.VOLUME,
        device=resolved.device,
        device_source=resolved.source,
        mount_point=None,
        ntfs_path=None,
        inode=None,
    )

    result.raw_sections["mmls"] = run_mmls(tools["mmls"], resolved, log)
    result.raw_sections["fsstat"] = run_fsstat(tools["fsstat"], resolved, log)

    suspicious_patterns = config_list(config, "suspicious_path_patterns")
    executable_extensions = {
        ext if ext.startswith(".") else f".{ext}"
        for ext in config_list(config, "executable_extensions")
    }
    fls_findings: list[Finding] = []

    for raw_path in config_list(config, "volume_scan_paths"):
        ntfs_path = raw_path if raw_path.startswith("/") else f"/{raw_path}"
        log.step(f"Listing NTFS path {ntfs_path} via fls")
        fls_output = run_fls(tools["fls"], resolved, ntfs_path, log)
        result.raw_sections[f"fls:{ntfs_path}"] = fls_output
        fls_findings.extend(
            fls_path_findings(
                fls_output,
                suspicious_patterns=suspicious_patterns,
                executable_extensions=executable_extensions,
            )
        )

    result.findings.extend(fls_findings)
    if not fls_findings:
        result.findings.append(
            Finding(
                Severity.INFO,
                "volume_scan",
                "No suspicious executables were flagged in configured volume scan paths.",
            )
        )
    return result


def analyze_file_entry(target, resolved, mount_point, ntfs_path, config, tools, log):
    threshold = config_int(config, "timestomp_seconds_threshold", 60)
    inode = run_ifind(tools["ifind"], resolved, ntfs_path, log)
    scope = TargetScope.FILE if target.is_file() else TargetScope.DIRECTORY
    result = AnalysisResult(
        target=target,
        scope=scope,
        device=resolved.device,
        device_source=resolved.source,
        mount_point=mount_point,
        ntfs_path=ntfs_path,
        inode=inode,
    )

    if inode is None:
        result.findings.append(
            Finding(
                Severity.ALERT,
                "missing_mft_entry",
                f"No MFT entry found for NTFS path `{ntfs_path}`.",
            )
        )
        return result

    istat_output = run_istat(tools["istat"], resolved, inode, log)
    result.raw_sections["istat"] = istat_output
    result.findings.extend(analyze_istat_output(istat_output, threshold))
    if not result.findings:
        result.findings.append(
            Finding(
                Severity.INFO,
                "clean",
                "No filesystem-level anomalies detected for this MFT entry.",
            )
        )
    return result


def iter_directory_files(target, max_files):
    files: list[Path] = []
    for path in sorted(target.rglob("*")):
        if not path.is_file():
            continue
        files.append(path)
        if max_files > 0 and len(files) >= max_files:
            break
    return files


def analyze_directory(target, resolved, mount_point, config, tools, log):
    max_files = config_int(config, "max_directory_files", 5000)
    files = iter_directory_files(target, max_files)
    log.step(f"Analyzing {len(files)} file(s) under {target} at the NTFS layer")

    aggregate = AnalysisResult(
        target=target,
        scope=TargetScope.DIRECTORY,
        device=resolved.device,
        device_source=resolved.source,
        mount_point=mount_point,
        ntfs_path=None,
        inode=None,
    )

    suspect_count = 0
    for index, file_path in enumerate(files, start=1):
        ntfs_path = ntfs_path_for_target(file_path, mount_point)
        log.step(f"[{index}/{len(files)}] {ntfs_path}")
        entry = analyze_file_entry(
            file_path,
            resolved,
            mount_point,
            ntfs_path,
            config,
            tools,
            log,
        )
        for finding in entry.findings:
            if finding.severity in {Severity.SUSPECT, Severity.ALERT}:
                suspect_count += 1
            aggregate.findings.append(
                Finding(
                    finding.severity,
                    finding.category,
                    f"{ntfs_path}: {finding.detail}",
                )
            )

    aggregate.raw_sections["files_analyzed"] = str(len(files))
    if suspect_count == 0:
        aggregate.findings.append(
            Finding(
                Severity.INFO,
                "directory_scan",
                f"No filesystem-level anomalies detected in {len(files)} file(s).",
            )
        )
    else:
        aggregate.findings.append(
            Finding(
                Severity.SUSPECT,
                "directory_scan",
                f"Flagged {suspect_count} suspect filesystem indicator(s) across {len(files)} file(s).",
            )
        )
    return aggregate


def marker_line(target, fingerprint):
    return f"{MARKER_PREFIX}target={target} fingerprint={fingerprint} -->"


def section_exists(existing, target, fingerprint):
    return marker_line(target, fingerprint) in existing


def format_findings_table(findings):
    if not findings:
        return ["_No findings._", ""]
    lines = [
        "| Severity | Category | Detail |",
        "| --- | --- | --- |",
    ]
    for item in findings:
        lines.append(f"| {item.severity.value} | {item.category} | {item.detail} |")
    lines.append("")
    return lines


def format_analysis_section(result):
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = [
        marker_line(result.target, result.fingerprint()),
        f"## Analysis — {timestamp}",
        "",
        f"- **Target:** `{result.target}`",
        f"- **Scope:** `{result.scope.value}`",
    ]
    if result.device is not None:
        lines.append(f"- **Device:** `{result.device}`")
    if result.device_source:
        lines.append(f"- **Device source:** `{result.device_source}`")
    if result.mount_point is not None:
        lines.append(f"- **Mount point:** `{result.mount_point}`")
    if result.ntfs_path:
        lines.append(f"- **NTFS path:** `{result.ntfs_path}`")
    if result.inode is not None:
        lines.append(f"- **MFT inode:** `{result.inode}`")
    lines.extend(["", "### Findings", ""])
    lines.extend(format_findings_table(result.findings))

    for section_name, content in result.raw_sections.items():
        if not content.strip():
            continue
        lines.extend([f"### Raw: {section_name}", "", "```", content.strip(), "```", ""])

    return "\n".join(lines)


def append_report(output, section, result, log):
    output.parent.mkdir(parents=True, exist_ok=True)
    existing = output.read_text(encoding="utf-8") if output.is_file() else ""

    if section_exists(existing, result.target, result.fingerprint()):
        log.step(
            f"Skipping write; identical analysis already recorded for `{result.target}` "
            f"(fingerprint {result.fingerprint()})"
        )
        return

    pieces: list[str] = []
    if not existing.strip():
        pieces.append("# sleuthkit-ntfs Report\n")
    pieces.append(section)
    pieces.append("\n---\n")
    output.write_text(existing + "".join(pieces), encoding="utf-8")
    log.step(f"Appended analysis for `{result.target}` to {output}")


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
    del flagged_csv, file_list

    log = KirbyLogger(verbose, prefix="sleuthkit-ntfs")
    log.step(f"Loading config from {config}")
    settings = load_config(config)
    sleuthkit_settings = load_sleuthkit_settings(log)

    prefix = project_path(settings, "sleuthkit_prefix")
    tools = {
        name: find_tool(name, prefix, log)
        for name in ("mmls", "fsstat", "fls", "ifind", "istat")
    }

    target = target.resolve(strict=False)
    scope = classify_target(target)
    log.step(f"Target scope: {scope.value}")

    if scope is TargetScope.VOLUME:
        resolved, mount_point = resolve_ntfs_image(target, sleuthkit_settings, settings, log)
        result = analyze_volume(target, resolved, settings, tools, log)
        if mount_point is not None:
            result.mount_point = mount_point
    else:
        resolved, mount_point = resolve_ntfs_image(target, sleuthkit_settings, settings, log)
        if mount_point is None:
            raise RuntimeError("Could not determine mount point for directory/file analysis.")

        if scope is TargetScope.FILE:
            ntfs_path = ntfs_path_for_target(target, mount_point)
            result = analyze_file_entry(
                target,
                resolved,
                mount_point,
                ntfs_path,
                settings,
                tools,
                log,
            )
        else:
            result = analyze_directory(
                target,
                resolved,
                mount_point,
                settings,
                tools,
                log,
            )

    append_report(output, format_analysis_section(result), result, log)
