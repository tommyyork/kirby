"""Signatures analysis module — verify code signatures on flagged executables."""

from __future__ import annotations

import configparser
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from kirby_flagged import load_flagged
from kirby_log import KirbyLogger
from kirby_report import format_config_lines, scan_timestamp

MODULE_DIR = Path(__file__).resolve().parent
CONFIG_SECTION = "signatures"
TOOL_NAMES = ("codesign", "osslsigncode", "exiftool", "strings")


def load_config(config_path: Path) -> configparser.ConfigParser:
    parser = configparser.ConfigParser()
    parser.read_string(f"[{CONFIG_SECTION}]\n{config_path.read_text(encoding='utf-8')}")
    return parser


def project_path(config: configparser.ConfigParser, key: str) -> Path:
    value = config.get(CONFIG_SECTION, key)
    path = Path(value)
    if path.is_absolute():
        return path
    return ROOT / path


def eligible_extensions(config: configparser.ConfigParser) -> set[str]:
    raw = config.get(CONFIG_SECTION, "extensions")
    extensions: set[str] = set()
    for item in raw.split(","):
        ext = item.strip().lower()
        if not ext:
            continue
        if not ext.startswith("."):
            ext = f".{ext}"
        extensions.add(ext)
    if not extensions:
        raise RuntimeError("No extensions configured for signatures module")
    return extensions


def resolve_tool(name: str) -> str | None:
    path = shutil.which(name)
    if path:
        return path

    for candidate in (
        Path("/opt/homebrew/bin") / name,
        Path("/usr/local/bin") / name,
    ):
        if candidate.is_file():
            return str(candidate)
    return None


def run_command(command: list[str], *, timeout: int = 120) -> tuple[int, str]:
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        return 127, f"command not found: {command[0]}"
    except subprocess.TimeoutExpired:
        return 124, f"command timed out after {timeout}s"

    output = completed.stdout
    if completed.stderr:
        if output:
            output = f"{output.rstrip()}\n{completed.stderr.rstrip()}"
        else:
            output = completed.stderr.rstrip()
    return completed.returncode, output.strip()


def read_flagged_executables(
    flagged_csv: Path,
    extensions: set[str],
    log: KirbyLogger,
) -> list[tuple[Path, list[str]]]:
    if not flagged_csv.is_file():
        log.step(f"No flagged file list at {flagged_csv}")
        return []

    flagged = load_flagged(flagged_csv)
    log.step(f"Loaded {len(flagged)} path(s) from {flagged_csv}")

    executables: list[tuple[Path, list[str]]] = []
    for path_str, (tools, _sha256) in sorted(flagged.items()):
        path = Path(path_str)
        if path.suffix.lower() not in extensions:
            continue
        if not path.is_file():
            log.step(f"Skipping missing file: {path}")
            continue
        executables.append((path, tools))

    log.step(f"Found {len(executables)} existing flagged executable(s) to analyze")
    return executables


def run_codesign(path: Path, tool: str | None) -> tuple[bool, str]:
    if tool is None:
        return False, "codesign: not found on PATH"

    verify_code, verify_output = run_command(
        [tool, "--verify", "--verbose=4", str(path)],
    )
    detail_code, detail_output = run_command(
        [tool, "-dv", "--verbose=4", str(path)],
    )

    sections = ["#### codesign", ""]
    sections.append("**verify**")
    sections.append("")
    sections.append("```")
    sections.append(verify_output or "(no output)")
    sections.append("```")
    sections.append("")
    sections.append("**details**")
    sections.append("")
    sections.append("```")
    sections.append(detail_output or "(no output)")
    sections.append("```")

    return verify_code == 0, "\n".join(sections)


def run_osslsigncode(path: Path, tool: str | None) -> tuple[bool, str]:
    if tool is None:
        return False, "osslsigncode: not found on PATH"

    code, output = run_command([tool, "verify", "-in", str(path)])
    sections = [
        "#### osslsigncode",
        "",
        "```",
        output or "(no output)",
        "```",
    ]
    return code == 0, "\n".join(sections)


def run_exiftool(path: Path, tool: str | None) -> str:
    if tool is None:
        return "#### exiftool\n\n```\nexiftool: not found on PATH\n```"

    code, output = run_command([tool, str(path)])
    sections = [
        "#### exiftool",
        "",
        "```",
        output or "(no output)",
        "```",
    ]
    if code != 0:
        sections.append("")
        sections.append(f"_exiftool exited with code {code}_")
    return "\n".join(sections)


def run_strings(path: Path, tool: str | None, limit: int) -> str:
    if tool is None:
        return "#### strings\n\n```\nstrings: not found on PATH\n```"

    code, output = run_command([tool, str(path)])
    lines = [line for line in output.splitlines() if line.strip()]
    limited = lines[:limit]
    rendered = "\n".join(limited) if limited else "(no strings found)"

    sections = [
        "#### strings",
        "",
        f"_First {limit} non-empty line(s):_",
        "",
        "```",
        rendered,
        "```",
    ]
    if code != 0:
        sections.append("")
        sections.append(f"_strings exited with code {code}_")
    return "\n".join(sections)


def analyze_executable(
    path: Path,
    scan_tools: list[str],
    tools: dict[str, str | None],
    strings_limit: int,
) -> str:
    codesign_ok, codesign_section = run_codesign(path, tools["codesign"])
    osslsigncode_ok, osslsigncode_section = run_osslsigncode(path, tools["osslsigncode"])
    signature_valid = codesign_ok or osslsigncode_ok

    lines = [
        f"### `{path}`",
        "",
        f"- **flagged_by:** `{', '.join(scan_tools)}`",
        f"- **signature_valid:** `{'yes' if signature_valid else 'no'}`",
        f"- **codesign:** `{'valid' if codesign_ok else 'invalid or not applicable'}`",
        f"- **osslsigncode:** `{'valid' if osslsigncode_ok else 'invalid or not applicable'}`",
        "",
        codesign_section,
        "",
        osslsigncode_section,
    ]

    if not signature_valid:
        lines.extend(
            [
                "",
                "#### Additional analysis (signature check failed)",
                "",
                run_exiftool(path, tools["exiftool"]),
                "",
                run_strings(path, tools["strings"], strings_limit),
            ]
        )

    lines.append("")
    lines.append("---")
    lines.append("")
    return "\n".join(lines)


def format_report(
    target: Path | None,
    flagged_csv: Path,
    config: configparser.ConfigParser,
    executable_count: int,
    result_sections: list[str],
    *,
    scan_time: str,
) -> str:
    if target is None:
        target_label = f"(not provided; using `{flagged_csv}`)"
    else:
        target_label = f"`{target}`"

    lines = [
        "# Signatures Analysis Report",
        "",
        f"Target Directory: {target_label}",
        f"Scan Time: {scan_time}",
        *format_config_lines(config, CONFIG_SECTION),
        "",
        "## Summary",
        "",
        f"- **Flagged executables analyzed:** {executable_count}",
        f"- **Results sections:** {len(result_sections)}",
        "",
    ]

    if result_sections:
        lines.extend(["## Results", ""])
        lines.extend(result_sections)
    else:
        lines.extend(["## Results", "", "No flagged executables to analyze.", ""])

    return "\n".join(lines)


def run(
    target: Path | None,
    output: Path,
    config: Path,
    *,
    verbose: bool = True,
    flagged_csv: Path | None = None,
) -> None:
    log = KirbyLogger(verbose, prefix="signatures")
    log.step(f"Loading config from {config}")
    settings = load_config(config)

    flagged_csv_path = flagged_csv or project_path(settings, "flagged_csv")
    extensions = eligible_extensions(settings)
    strings_limit = settings.getint(CONFIG_SECTION, "strings_limit", fallback=10)

    tools = {name: resolve_tool(name) for name in TOOL_NAMES}
    for name, path in tools.items():
        if path:
            log.step(f"Using {name} from {path}")
        else:
            log.step(f"Warning: {name} not found on PATH")

    executables = read_flagged_executables(flagged_csv_path, extensions, log)
    result_sections: list[str] = []

    for path, scan_tools in log.progress(
        executables,
        total=len(executables),
        desc="Checking signatures",
        unit="file",
    ):
        log.step(f"Analyzing {path}")
        result_sections.append(
            analyze_executable(path, scan_tools, tools, strings_limit),
        )

    log.step(f"Writing report to {output}")
    report = format_report(
        target=target,
        flagged_csv=flagged_csv_path,
        config=settings,
        executable_count=len(executables),
        result_sections=result_sections,
        scan_time=scan_timestamp(),
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(report, encoding="utf-8")
