"""RegRipper module — parse Windows registry hives for persistence indicators."""

from __future__ import annotations

import configparser
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from kirby_flagged import fill_flagged_file_hashes, record_flagged
from kirby_log import KirbyLogger
from kirby_report import format_scan_report_header
from kirby_tool_errors import check_subprocess, tool_failure_message, handle_tool_failure

MODULE_DIR = Path(__file__).resolve().parent
TOOL_NAME = "regripper"

PLUGIN_MAP: dict[str, list[tuple[str, str]]] = {
    "run": [("software", "run"), ("ntuser", "run")],
    "services": [("system", "services")],
    "winlogon": [("software", "winlogon_tln")],
    "userassist": [("ntuser", "userassist")],
    "appcompatcache": [("system", "appcompatcache")],
}

CATEGORY_TITLES = {
    "run": "Run Keys",
    "services": "Services",
    "winlogon": "Winlogon",
    "userassist": "UserAssist",
    "appcompatcache": "AppCompatCache",
}

ALERT_PATTERN = re.compile(r"ALERT", re.IGNORECASE)
RUN_ENTRY_PATTERN = re.compile(r"^\s{2}(.+?)\s+-\s+(.+)$")
RUN_SUBKEY_ENTRY_PATTERN = re.compile(r"^\s{2}(.+?)\s+->\s+(.+)$")
SERVICE_IMAGEPATH_PATTERN = re.compile(r"^\s{2}ImagePath\s*=\s*(.+)$", re.IGNORECASE)
SERVICE_NAME_PATTERN = re.compile(r"^\s{2}Name\s*=\s*(.+)$", re.IGNORECASE)
USERASSIST_PATH_PATTERN = re.compile(
    r"^(\s*)([A-Za-z]:\\.+?)(?:\s+\(\d+\))?\s*$",
)
TRAILING_USERASSIST_COUNT = re.compile(r"\s+\(\d+\)$")
TRAILING_TIMESTAMP = re.compile(r"\s{2,}\d{4}-\d{2}-\d{2}(?:\s+\d{2}:\d{2}:\d{2})?$")
WINDOWS_DRIVE_PATH = re.compile(r"^[A-Za-z]:\\", re.IGNORECASE)
QUOTED_PATH = re.compile(r'^"\s*([^"]+?)\s*"')
EXECUTABLE_PATTERN = re.compile(
    r"\.(?:exe|dll|bat|cmd|ps1|vbs|js|jse|wsf|wsh|scr|com|msi|hta|jar|lnk)\b",
    re.IGNORECASE,
)
SUSPICIOUS_LAUNCHER_PATTERN = re.compile(
    r"(?:powershell(?:\.exe)?|pwsh(?:\.exe)?|cmd(?:\.exe)?|wscript(?:\.exe)?|"
    r"cscript(?:\.exe)?|mshta(?:\.exe)?|rundll32(?:\.exe)?|regsvr32(?:\.exe)?|"
    r"bitsadmin(?:\.exe)?|certutil(?:\.exe)?|msbuild(?:\.exe)?|wmic(?:\.exe)?|"
    r"schtasks(?:\.exe)?|(?:^|[\s\"'])reg\.exe\b|forfiles(?:\.exe)?|"
    r"scriptrunner(?:\.exe)?|cmstp(?:\.exe)?|(?:^|[\s\"'])msdt\.exe\b)",
    re.IGNORECASE,
)
SUSPICIOUS_PATH_PATTERN = re.compile(
    r"(?:\\temp\\|\\tmp\\|\\appdata\\[^\\]+\\local\\temp\\|"
    r"\\recycle|\\globalroot\\|\\downloads\\|\\perflogs\\|"
    r"\\appdata\\roaming\\[^\\]+\\[^\\]+\.(?:exe|dll|bat|ps1|vbs|js|hta)\b|"
    r"\\windows\\temp\\|\\system volume information\\|"
    r"\\programdata\\[^\\]+\\[^\\]+\.(?:exe|dll|bat|ps1|vbs|js|hta)\b)",
    re.IGNORECASE,
)
LEGITIMATE_PATH_PATTERN = re.compile(
    r"(?:\\programdata\\microsoft\\|\\windows\\|\\program files(?: \(x86\))?\\|"
    r"\\users\\public\\desktop\\.*\.lnk$)",
    re.IGNORECASE,
)
ENV_VAR_PATTERN = re.compile(r"%([^%]+)%", re.IGNORECASE)
REGISTRY_ALERT_PATH_PATTERN = re.compile(
    r"\|ALERT\|\|\|(.+?)\s+(?:Shell|Userinit|TaskMan|System|Notify|SpecialAccounts)",
    re.IGNORECASE,
)
WINLOGON_SHELL_VALUE_PATTERN = re.compile(
    r"Shell value not explorer\.exe:\s*(.+?)\s*$",
    re.IGNORECASE,
)
REGISTRY_ALERT_FILE_PATH_PATTERN = re.compile(
    r"found in path:\s*(.+)$",
    re.IGNORECASE,
)
USERASSIST_REGISTRY_PATH = (
    "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist"
)
SERVICES_REGISTRY_PREFIX = "ControlSet001\\Services"


@dataclass
class Finding:
    category: str
    hive_label: str
    reason: str
    detail: str
    source_path: str | None = None
    registry_path: str | None = None
    flagged_path: Path | None = None


@dataclass
class ScanContext:
    target: Path
    system_hive: Path | None = None
    software_hive: Path | None = None
    ntuser_hives: list[tuple[str, Path]] = field(default_factory=list)


def load_config(config_path: Path) -> configparser.ConfigParser:
    parser = configparser.ConfigParser()
    parser.read_string(f"[regripper]\n{config_path.read_text(encoding='utf-8')}")
    return parser


def config_list(config: configparser.ConfigParser, key: str) -> list[str]:
    raw = config.get("regripper", key, fallback="")
    return [item.strip() for item in raw.split(",") if item.strip()]


def repo_dir(config: configparser.ConfigParser) -> Path:
    return MODULE_DIR / config.get("regripper", "repo", fallback="RegRipper4.0")


def perl5lib_dir(config: configparser.ConfigParser) -> Path:
    return MODULE_DIR / "perl-lib" / "lib" / "perl5"


def patch_rip_alert_msg(rip_pl: Path, log: KirbyLogger) -> None:
    """RegRipper 4.0 rip.pl omits alertMsg() but several plugins still call it."""
    text = rip_pl.read_text(encoding="utf-8")
    if "sub alertMsg" in text:
        return

    marker = "# Kirby patch: restore alertMsg() for TLN/alert plugins"
    insert = f"""{marker}
sub alertMsg {{
\t::rptMsg($_[0]);
}}

"""
    anchor = "sub parsePluginsFile"
    if anchor not in text:
        raise RuntimeError(f"Could not patch alertMsg into {rip_pl}")

    rip_pl.write_text(text.replace(anchor, insert + anchor, 1), encoding="utf-8")
    log.step(f"Patched {rip_pl.name} with missing alertMsg() helper")


def ensure_regripper(config: configparser.ConfigParser, log: KirbyLogger) -> Path:
    regripper = repo_dir(config)
    if not regripper.is_dir():
        url = config.get("regripper", "repo_url")
        log.step(f"Cloning RegRipper from {url}")
        subprocess.run(
            ["git", "clone", "--depth", "1", url, str(regripper)],
            check=True,
        )

    rip_pl = regripper / "rip.pl"
    if not rip_pl.is_file():
        raise FileNotFoundError(f"RegRipper entrypoint not found: {rip_pl}")

    marker = MODULE_DIR / "perl-lib" / ".setup-complete"
    if not marker.is_file():
        setup = MODULE_DIR / "setup.sh"
        if not setup.is_file():
            raise FileNotFoundError(f"Setup script not found: {setup}")
        log.step("Building local RegRipper Perl environment")
        subprocess.run(["bash", str(setup)], check=True, cwd=MODULE_DIR)
    else:
        log.step("RegRipper Perl environment already built")

    patch_rip_alert_msg(rip_pl, log)
    return rip_pl


def discover_hives(target: Path, config: configparser.ConfigParser, log: KirbyLogger) -> ScanContext:
    ctx = ScanContext(target=target)
    system_rel = config.get("regripper", "system_hive")
    software_rel = config.get("regripper", "software_hive")
    users_rel = config.get("regripper", "users_dir")
    skip_profiles = {name.casefold() for name in config_list(config, "skip_user_profiles")}

    system_path = target / system_rel
    software_path = target / software_rel
    if system_path.is_file():
        ctx.system_hive = system_path
        log.step(f"Found SYSTEM hive: {system_path}")
    else:
        log.step(f"SYSTEM hive not found at {system_path}")

    if software_path.is_file():
        ctx.software_hive = software_path
        log.step(f"Found SOFTWARE hive: {software_path}")
    else:
        log.step(f"SOFTWARE hive not found at {software_path}")

    users_dir = target / users_rel
    if users_dir.is_dir():
        for profile_dir in sorted(users_dir.iterdir()):
            if not profile_dir.is_dir():
                continue
            if profile_dir.name.casefold() in skip_profiles:
                continue
            ntuser = profile_dir / "NTUSER.DAT"
            if ntuser.is_file():
                ctx.ntuser_hives.append((profile_dir.name, ntuser))
        log.step(f"Found {len(ctx.ntuser_hives)} NTUSER.DAT hive(s)")
    else:
        log.step(f"Users directory not found at {users_dir}")

    return ctx


def hive_for_type(ctx: ScanContext, hive_type: str) -> list[tuple[str, Path]]:
    if hive_type == "system" and ctx.system_hive:
        return [("SYSTEM", ctx.system_hive)]
    if hive_type == "software" and ctx.software_hive:
        return [("SOFTWARE", ctx.software_hive)]
    if hive_type == "ntuser":
        return [(f"NTUSER.DAT ({username})", path) for username, path in ctx.ntuser_hives]
    return []


def run_plugin(
    rip_pl: Path,
    perl5lib: Path,
    hive_path: Path,
    plugin: str,
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PERL5LIB"] = str(perl5lib)
    return subprocess.run(
        ["perl", str(rip_pl), "-r", str(hive_path), "-p", plugin],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )


def expand_windows_env(value: str) -> str:
    replacements = {
        "systemroot": "Windows",
        "windir": "Windows",
        "programfiles": "Program Files",
        "programfiles(x86)": "Program Files (x86)",
        "programdata": "ProgramData",
        "userprofile": "Users",
        "appdata": "Users",
        "localappdata": "Users",
        "temp": "Windows/Temp",
        "tmp": "Windows/Temp",
    }

    def replace(match: re.Match[str]) -> str:
        key = match.group(1).strip().casefold()
        return replacements.get(key, match.group(0))

    expanded = ENV_VAR_PATTERN.sub(replace, value)
    return expanded.strip().strip('"')


def strip_registry_path_metadata(value: str) -> str:
    path = value.strip().strip('"\'')
    path = TRAILING_USERASSIST_COUNT.sub("", path)
    path = TRAILING_TIMESTAMP.sub("", path)
    return path.strip()


def normalize_windows_path_for_mount(path: str) -> str:
    normalized = path.replace("/", "\\")
    if normalized.casefold().startswith("\\\\?\\"):
        return normalized[4:]
    return normalized


def extract_windows_path(value: str) -> str | None:
    """Extract a Windows path from a registry value, alert line, or command string."""
    cleaned = expand_windows_env(value)
    if not cleaned:
        return None

    quoted = QUOTED_PATH.match(cleaned)
    if quoted:
        candidate = strip_registry_path_metadata(quoted.group(1))
        return candidate or None

    cleaned = strip_registry_path_metadata(cleaned)
    normalized = cleaned.replace("/", "\\")

    drive_match = re.search(r"(?:\\\\\?\\)?([A-Za-z]:\\)", normalized, re.IGNORECASE)
    if drive_match:
        path_from_drive = normalize_windows_path_for_mount(normalized[drive_match.start() :])

        ext_match = EXECUTABLE_PATTERN.search(path_from_drive)
        if ext_match:
            return path_from_drive[: ext_match.end()]

        if WINDOWS_DRIVE_PATH.match(path_from_drive):
            return path_from_drive

    token = cleaned.split()[0].strip('"\'') if cleaned.split() else cleaned
    token = strip_registry_path_metadata(token)
    if EXECUTABLE_PATTERN.search(token) or WINDOWS_DRIVE_PATH.match(token):
        return normalize_windows_path_for_mount(token)
    if SUSPICIOUS_LAUNCHER_PATTERN.search(cleaned):
        return cleaned
    return None


def extract_executable(value: str) -> str | None:
    return extract_windows_path(value)


def resolve_target_path(raw_path: str, target: Path) -> Path | None:
    candidate = extract_windows_path(raw_path)
    if not candidate:
        return None

    normalized = normalize_windows_path_for_mount(candidate)
    if not WINDOWS_DRIVE_PATH.match(normalized):
        return None

    rel = normalized[3:].replace("\\", "/")
    resolved = (target / rel).resolve()
    try:
        resolved.relative_to(target.resolve())
    except ValueError:
        return None
    return resolved


def resolve_bare_windows_path(value: str, target: Path) -> Path | None:
    """Resolve a Windows path or bare executable name to a path on the target volume."""
    cleaned = expand_windows_env(value.strip().strip('"\''))
    if not cleaned:
        return None

    resolved = resolve_target_path(cleaned, target)
    if resolved:
        return resolved

    token = extract_windows_path(cleaned)
    if not token:
        return None
    if WINDOWS_DRIVE_PATH.match(token):
        return None

    bare_name = token
    search_roots = (
        target / "Windows" / "System32",
        target / "Windows" / "SysWOW64",
        target / "Windows",
    )

    if EXECUTABLE_PATTERN.search(bare_name):
        for root in search_roots:
            candidate = (root / bare_name).resolve()
            try:
                candidate.relative_to(target.resolve())
            except ValueError:
                continue
            if candidate.is_file():
                return candidate
        return (target / "Windows" / "System32" / bare_name).resolve()

    # Non-path shell tokens (e.g. Winlogon Shell value "0")
    if re.fullmatch(r"[\w.-]+", bare_name):
        return (target / "Windows" / "System32" / bare_name).resolve()

    return None


def extract_winlogon_shell_value(line: str) -> str | None:
    match = WINLOGON_SHELL_VALUE_PATTERN.search(line)
    if not match:
        return None
    return match.group(1).strip()


def extract_registry_path_from_alert(line: str) -> str | None:
    match = REGISTRY_ALERT_PATH_PATTERN.search(line)
    if match:
        return match.group(1).strip()
    return None


def is_suspicious_value(value: str) -> list[str]:
    reasons: list[str] = []
    expanded = expand_windows_env(value)
    normalized = expanded.replace("/", "\\")
    if LEGITIMATE_PATH_PATTERN.search(normalized):
        return reasons
    if SUSPICIOUS_LAUNCHER_PATTERN.search(expanded):
        reasons.append("suspicious launcher")
    if SUSPICIOUS_PATH_PATTERN.search(normalized):
        reasons.append("suspicious path")
    return reasons


def add_finding(
    findings: list[Finding],
    *,
    category: str,
    hive_label: str,
    reason: str,
    detail: str,
    value: str | None,
    target: Path,
    registry_path: str | None = None,
) -> None:
    flagged_path = None
    if value:
        flagged_path = resolve_target_path(value, target) or resolve_bare_windows_path(value, target)

    findings.append(
        Finding(
            category=category,
            hive_label=hive_label,
            reason=reason,
            detail=detail,
            source_path=value,
            registry_path=registry_path or extract_registry_path_from_alert(detail),
            flagged_path=flagged_path,
        )
    )


def analyze_run_output(
    output: str,
    *,
    category: str,
    hive_label: str,
    target: Path,
) -> list[Finding]:
    findings: list[Finding] = []
    current_key = "unknown"

    for line in output.splitlines():
        if ALERT_PATTERN.search(line):
            add_finding(
                findings,
                category=category,
                hive_label=hive_label,
                reason="RegRipper alert",
                detail=line.strip(),
                value=line,
                target=target,
            )
            continue

        stripped = line.strip()
        if stripped and not stripped.startswith("LastWrite") and " not found" not in stripped:
            if not stripped.startswith("  ") and not stripped.startswith("run v."):
                if "\\" in stripped or stripped.endswith("Run") or "RunOnce" in stripped:
                    current_key = stripped

        match = RUN_ENTRY_PATTERN.match(line) or RUN_SUBKEY_ENTRY_PATTERN.match(line)
        if not match:
            continue

        name, value = match.group(1).strip(), match.group(2).strip()
        reasons = is_suspicious_value(value)
        if reasons:
            add_finding(
                findings,
                category=category,
                hive_label=hive_label,
                reason=", ".join(reasons),
                detail=f"{current_key} → {name}: {value}",
                value=value,
                target=target,
                registry_path=current_key,
            )

    return findings


def analyze_services_output(
    output: str,
    *,
    category: str,
    hive_label: str,
    target: Path,
) -> list[Finding]:
    findings: list[Finding] = []
    current_name = "unknown"
    current_imagepath: str | None = None

    for line in output.splitlines():
        if ALERT_PATTERN.search(line):
            add_finding(
                findings,
                category=category,
                hive_label=hive_label,
                reason="RegRipper alert",
                detail=line.strip(),
                value=line,
                target=target,
            )
            continue

        name_match = SERVICE_NAME_PATTERN.match(line)
        if name_match:
            current_name = name_match.group(1).strip()
            current_imagepath = None
            continue

        image_match = SERVICE_IMAGEPATH_PATTERN.match(line)
        if image_match:
            current_imagepath = image_match.group(1).strip()
            reasons = is_suspicious_value(current_imagepath)
            if reasons:
                add_finding(
                    findings,
                    category=category,
                    hive_label=hive_label,
                    reason=", ".join(reasons),
                    detail=f"{current_name}: ImagePath = {current_imagepath}",
                    value=current_imagepath,
                    target=target,
                    registry_path=f"{SERVICES_REGISTRY_PREFIX}\\{current_name}",
                )
            continue

        if current_imagepath and line.strip() == "":
            current_name = "unknown"
            current_imagepath = None

    return findings


def analyze_winlogon_output(
    output: str,
    *,
    category: str,
    hive_label: str,
    target: Path,
) -> list[Finding]:
    findings: list[Finding] = []
    for line in output.splitlines():
        if not ALERT_PATTERN.search(line):
            continue

        detail = line.strip()
        registry_key = extract_registry_path_from_alert(detail)
        shell_value = extract_winlogon_shell_value(detail)

        add_finding(
            findings,
            category=category,
            hive_label=hive_label,
            reason="RegRipper alert",
            detail=detail,
            value=shell_value,
            target=target,
            registry_path=registry_key,
        )

    return findings


def analyze_userassist_output(
    output: str,
    *,
    category: str,
    hive_label: str,
    target: Path,
) -> list[Finding]:
    findings: list[Finding] = []
    for line in output.splitlines():
        if ALERT_PATTERN.search(line):
            add_finding(
                findings,
                category=category,
                hive_label=hive_label,
                reason="RegRipper alert",
                detail=line.strip(),
                value=line,
                target=target,
            )
            continue

        match = USERASSIST_PATH_PATTERN.match(line)
        if not match:
            continue

        path_value = match.group(2).strip()
        reasons = is_suspicious_value(path_value)
        if reasons:
            add_finding(
                findings,
                category=category,
                hive_label=hive_label,
                reason=", ".join(reasons),
                detail=path_value,
                value=path_value,
                target=target,
                registry_path=USERASSIST_REGISTRY_PATH,
            )

    return findings


def analyze_appcompatcache_output(
    output: str,
    *,
    category: str,
    hive_label: str,
    target: Path,
) -> list[Finding]:
    findings: list[Finding] = []
    for line in output.splitlines():
        if not ALERT_PATTERN.search(line):
            continue
        add_finding(
            findings,
            category=category,
            hive_label=hive_label,
            reason="RegRipper alert",
            detail=line.strip(),
            value=line,
            target=target,
        )

        path_match = REGISTRY_ALERT_FILE_PATH_PATTERN.search(line)
        if path_match:
            path_value = path_match.group(1).strip()
            add_finding(
                findings,
                category=category,
                hive_label=hive_label,
                reason="suspicious path",
                detail=path_value,
                value=path_value,
                target=target,
                registry_path="ControlSet001\\Control\\Session Manager\\AppCompatCache",
            )
    return dedupe_findings(findings)


def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, str, str]] = set()
    unique: list[Finding] = []
    for item in findings:
        key = (item.category, item.hive_label, item.reason, item.detail)
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique


ANALYZERS = {
    "run": analyze_run_output,
    "services": analyze_services_output,
    "winlogon": analyze_winlogon_output,
    "userassist": analyze_userassist_output,
    "appcompatcache": analyze_appcompatcache_output,
}


def collect_flagged_entries(findings: list[Finding]) -> tuple[list[Path], list[str]]:
    filesystem_paths: dict[str, Path] = {}
    registry_paths: set[str] = set()

    for item in findings:
        if item.registry_path:
            registry_paths.add(item.registry_path)
        if item.flagged_path:
            filesystem_paths[str(item.flagged_path).lower()] = item.flagged_path

    filesystem = sorted(filesystem_paths.values(), key=lambda path: str(path).lower())
    registry = sorted(registry_paths, key=str.lower)
    return filesystem, registry


def format_summary_table(findings: list[Finding]) -> list[str]:
    counts: dict[str, int] = {}
    for item in findings:
        counts[item.category] = counts.get(item.category, 0) + 1

    lines = [
        "## Summary",
        "",
        "| Category | Findings |",
        "|----------|----------|",
    ]
    for category in sorted(CATEGORY_TITLES):
        lines.append(f"| {CATEGORY_TITLES[category]} | {counts.get(category, 0)} |")
    lines.append(f"| **Total** | **{len(findings)}** |")
    lines.append("")
    return lines


def format_findings_section(category: str, findings: list[Finding]) -> list[str]:
    category_findings = [item for item in findings if item.category == category]
    lines = [f"## {CATEGORY_TITLES[category]}", ""]
    if not category_findings:
        lines.append("_No suspect entries detected._")
        lines.append("")
        return lines

    for index, item in enumerate(category_findings, start=1):
        lines.append(f"### {index}. {item.reason}")
        lines.append("")
        lines.append(f"- **Hive:** {item.hive_label}")
        if item.registry_path:
            lines.append(f"- **Registry path:** `{item.registry_path}`")
        lines.append(f"- **Detail:** {item.detail}")
        if item.source_path and item.source_path != item.detail:
            lines.append(f"- **Source:** `{item.source_path}`")
        if item.flagged_path:
            lines.append(f"- **Resolved file:** `{item.flagged_path}`")
        elif item.category == "winlogon" and item.source_path:
            lines.append(f"- **Shell value:** `{item.source_path}`")
        lines.append("")

    return lines


def format_report(
    target: Path,
    config: configparser.ConfigParser,
    ctx: ScanContext,
    findings: list[Finding],
    plugin_runs: list[str],
) -> str:
    lines = format_scan_report_header(
        "# RegRipper Scan Report",
        target,
        config,
        "regripper",
    )

    lines.extend(
        [
            "## Scope",
            "",
            f"- SYSTEM hive: `{ctx.system_hive}`" if ctx.system_hive else "- SYSTEM hive: _not found_",
            f"- SOFTWARE hive: `{ctx.software_hive}`" if ctx.software_hive else "- SOFTWARE hive: _not found_",
            f"- NTUSER.DAT hives: {len(ctx.ntuser_hives)}",
        ]
    )
    for username, path in ctx.ntuser_hives:
        lines.append(f"  - `{username}` → `{path}`")
    lines.extend(["", "## Plugins Run", ""])
    if plugin_runs:
        lines.extend(f"- {entry}" for entry in plugin_runs)
    else:
        lines.append("_No plugins executed._")
    lines.append("")

    lines.extend(format_summary_table(findings))

    if findings:
        lines.extend(["## Findings", ""])
        for category in sorted(CATEGORY_TITLES):
            lines.extend(format_findings_section(category, findings))
    else:
        lines.extend(["## Findings", "", "_No suspect registry entries detected._", ""])

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
    log = KirbyLogger(verbose, prefix="regripper")
    log.step(f"Loading config from {config}")
    settings = load_config(config)
    flagged_csv_path = flagged_csv or (
        file_list.parent / "flagged.csv" if file_list is not None else ROOT / "tmp" / "flagged.csv"
    )
    categories = config_list(settings, "categories") or list(CATEGORY_TITLES)

    rip_pl = ensure_regripper(settings, log)
    perl5lib = perl5lib_dir(settings)
    ctx = discover_hives(target.resolve(), settings, log)

    findings: list[Finding] = []
    plugin_runs: list[str] = []
    jobs: list[tuple[str, str, str, Path]] = []

    for category in categories:
        if category not in PLUGIN_MAP:
            log.step(f"Unknown category '{category}', skipping")
            continue
        for hive_type, plugin in PLUGIN_MAP[category]:
            for hive_label, hive_path in hive_for_type(ctx, hive_type):
                jobs.append((category, hive_label, plugin, hive_path))

    for category, hive_label, plugin, hive_path in log.progress(
        jobs,
        total=len(jobs),
        desc="Running RegRipper",
        unit="plugin",
    ):
        log.step(f"Running {plugin} against {hive_label}")
        result = run_plugin(rip_pl, perl5lib, hive_path, plugin)
        combined = f"{result.stdout or ''}\n{result.stderr or ''}".strip()
        plugin_runs.append(f"{plugin} → {hive_label} ({hive_path.name})")

        failure = tool_failure_message(
            f"RegRipper plugin {plugin} on {hive_label}",
            returncode=result.returncode,
            allowed_returncodes=frozenset({0}),
            stderr=result.stderr or "",
        )
        if failure:
            handle_tool_failure(failure, force_errors=force_errors)
            if not combined:
                continue

        analyzer = ANALYZERS.get(category)
        if analyzer:
            new_findings = analyzer(
                combined,
                category=category,
                hive_label=hive_label,
                target=target.resolve(),
            )
            for item in new_findings:
                location = item.registry_path or item.flagged_path or item.detail
                log.flag(f"{location} — {item.reason} ({CATEGORY_TITLES.get(category, category)})")
            findings.extend(new_findings)

    findings = dedupe_findings(findings)
    filesystem_paths, registry_paths = collect_flagged_entries(findings)
    updated = 0
    if filesystem_paths:
        updated += record_flagged(filesystem_paths, TOOL_NAME, csv_path=flagged_csv_path)
    if registry_paths:
        updated += record_flagged(
            registry_paths,
            TOOL_NAME,
            csv_path=flagged_csv_path,
            normalize=False,
        )
    if updated:
        log.step(
            f"Updated {updated} path(s) in {flagged_csv_path} "
            f"({len(filesystem_paths)} file, {len(registry_paths)} registry)"
        )

    if filesystem_paths:
        hashed = fill_flagged_file_hashes(
            flagged_csv_path,
            paths=filesystem_paths,
            compute_on_disk=True,
        )
        if hashed:
            log.step(f"Computed SHA-256 for {hashed} flagged file(s) in {flagged_csv_path}")

    log.step(f"Writing report to {output}")
    report = format_report(
        target=target.resolve(),
        config=settings,
        ctx=ctx,
        findings=findings,
        plugin_runs=plugin_runs,
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(report, encoding="utf-8")
    log.step(f"Found {len(findings)} suspect registry entries")
