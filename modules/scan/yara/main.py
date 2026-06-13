"""YARA scan module using Neo23x0's signature-base ruleset."""

from __future__ import annotations

import configparser
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from kirby_flagged import record_flagged
from kirby_kext import is_kext_target, kext_search_roots
from kirby_log import KirbyLogger
from kirby_report import format_scan_report_header

TOOL_NAME = "Yara"

MODULE_DIR = Path(__file__).resolve().parent
COMPILED_RULES_NAME = "kirby-compiled.yarc"
EXTERNAL_VARIABLE_RULES = "external-variable-rules.txt"


def load_config(config_path: Path) -> configparser.ConfigParser:
    parser = configparser.ConfigParser()
    parser.read_string(f"[yara]\n{config_path.read_text(encoding='utf-8')}")
    return parser


def ruleset_dir(config: configparser.ConfigParser) -> Path:
    return MODULE_DIR / config.get("yara", "ruleset")


def ruleset_url(config: configparser.ConfigParser) -> str:
    return config.get("yara", "ruleset_url")


def rules_dir(config: configparser.ConfigParser, base: Path) -> Path:
    return base / config.get("yara", "rules_dir", fallback="yara")


def is_ruleset_populated(path: Path, yara_rules: Path) -> bool:
    if not path.is_dir():
        return False
    return any(yara_rules.rglob("*.yar"))


def ensure_ruleset(config: configparser.ConfigParser, log: KirbyLogger) -> Path:
    base = ruleset_dir(config)
    yara_rules = rules_dir(config, base)

    if is_ruleset_populated(base, yara_rules):
        log.step(f"Ruleset already present at {base}")
        return base

    if base.exists() and not any(base.iterdir()):
        log.step(f"Removing empty ruleset directory {base}")
        base.rmdir()

    url = ruleset_url(config)
    log.step(f"Cloning ruleset from {url}")
    subprocess.run(
        ["git", "clone", "--depth", "1", url, str(base)],
        check=True,
    )

    if not is_ruleset_populated(base, yara_rules):
        raise RuntimeError(f"Ruleset clone succeeded but no .yar files found in {yara_rules}")

    log.step(f"Ruleset ready at {base}")
    return base


def excluded_rule_files(yara_rules: Path, log: KirbyLogger) -> set[Path]:
    exclude_list = yara_rules / EXTERNAL_VARIABLE_RULES
    if not exclude_list.is_file():
        log.step("No external-variable rule exclusions found")
        return set()

    excluded: set[Path] = set()
    for line in exclude_list.read_text(encoding="utf-8").splitlines():
        name = line.strip()
        if not name or name.startswith("#"):
            continue
        excluded.add((yara_rules / name).resolve())

    log.step(f"Excluding {len(excluded)} external-variable rule files")
    return excluded


def collect_rule_files(yara_rules: Path, log: KirbyLogger) -> list[Path]:
    log.step(f"Collecting rule files from {yara_rules}")
    excluded = excluded_rule_files(yara_rules, log)
    rule_files = sorted(
        path.resolve()
        for path in log.progress(
            yara_rules.rglob("*.yar"),
            desc="Collecting rules",
            unit="rule",
        )
        if path.resolve() not in excluded
    )
    if not rule_files:
        raise RuntimeError(f"No usable YARA rules found in {yara_rules}")
    log.step(f"Collected {len(rule_files)} rule files")
    return rule_files


def compiled_rules_path(base: Path) -> Path:
    return base / COMPILED_RULES_NAME


def needs_recompile(compiled: Path, rule_files: list[Path]) -> bool:
    if not compiled.is_file():
        return True
    compiled_mtime = compiled.stat().st_mtime
    return any(rule.stat().st_mtime > compiled_mtime for rule in rule_files)


def compile_rules(rule_files: list[Path], compiled: Path, log: KirbyLogger) -> None:
    yarac = shutil.which("yarac")
    if yarac is None:
        raise RuntimeError("yarac not found; install YARA (e.g. brew install yara)")

    log.step(f"Compiling {len(rule_files)} rules to {compiled}")
    subprocess.run([yarac, *[str(path) for path in rule_files], str(compiled)], check=True)
    log.step("Rule compilation complete")


def ensure_compiled_rules(
    base: Path,
    config: configparser.ConfigParser,
    log: KirbyLogger,
) -> tuple[Path, int]:
    yara_rules = rules_dir(config, base)
    rule_files = collect_rule_files(yara_rules, log)
    compiled = compiled_rules_path(base)

    if needs_recompile(compiled, rule_files):
        compile_rules(rule_files, compiled, log)
    else:
        log.step(f"Reusing compiled rules at {compiled}")

    return compiled, len(rule_files)


def run_yara(
    compiled: Path,
    target: Path,
    recursive: bool,
    log: KirbyLogger,
) -> subprocess.CompletedProcess[str]:
    yara = shutil.which("yara")
    if yara is None:
        raise RuntimeError("yara not found; install YARA (e.g. brew install yara)")

    command = [yara, "-C", str(compiled)]
    if recursive:
        command.append("-r")
    command.append(str(target))

    log.step(f"Running: {' '.join(command)}")
    log.step("Scanning target (this may take a while)")
    return subprocess.run(command, capture_output=True, text=True, check=False)


def run_yara_kext(
    compiled: Path,
    recursive: bool,
    log: KirbyLogger,
) -> tuple[list[tuple[str, str]], str, int]:
    roots = kext_search_roots()
    if not roots:
        raise RuntimeError("No kernel extension directories found on this system")

    matches: list[tuple[str, str]] = []
    stderr_parts: list[str] = []
    worst_returncode = 0

    for root in roots:
        result = run_yara(compiled, root, recursive, log)
        if result.returncode not in (0, 1):
            raise RuntimeError(result.stderr.strip() or f"yara exited with code {result.returncode}")
        worst_returncode = max(worst_returncode, result.returncode)
        matches.extend(parse_matches(result.stdout))
        if result.stderr.strip():
            stderr_parts.append(result.stderr.strip())

    return matches, "\n\n".join(stderr_parts), worst_returncode


def parse_matches(stdout: str) -> list[tuple[str, str]]:
    matches: list[tuple[str, str]] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            matches.append((parts[0], parts[1]))
    return matches


def format_report(
    target: Path,
    config: configparser.ConfigParser,
    rule_count: int,
    yara_version: str,
    matches: list[tuple[str, str]],
    stderr: str,
) -> str:
    lines = format_scan_report_header(
        "# YARA Scan Report",
        target,
        config,
        "yara",
    )
    lines.extend(
        [
            f"- **Rules compiled:** {rule_count}",
            f"- **YARA version:** {yara_version}",
            "",
        ]
    )

    if matches:
        lines.extend(
            [
                f"## Matches ({len(matches)})",
                "",
                "| Rule | File |",
                "| --- | --- |",
            ]
        )
        for rule, filepath in matches:
            lines.append(f"| `{rule}` | `{filepath}` |")
    else:
        lines.extend(["## Matches", "", "No matches found."])

    if stderr.strip():
        lines.extend(["", "## Warnings", "", "```", stderr.strip(), "```"])

    lines.append("")
    return "\n".join(lines)


def yara_version() -> str:
    yara = shutil.which("yara")
    if yara is None:
        return "unknown"
    result = subprocess.run([yara, "--version"], capture_output=True, text=True, check=False)
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
    log = KirbyLogger(verbose, prefix="yara")
    log.step(f"Loading config from {config}")
    settings = load_config(config)

    base = ensure_ruleset(settings, log)
    compiled, rule_count = ensure_compiled_rules(base, settings, log)
    recursive = settings.getboolean("yara", "recursive", fallback=True)
    log.step(f"Recursive scan: {recursive}")

    if is_kext_target(target):
        log.step("Scanning kernel extension directories")
        matches, stderr, _returncode = run_yara_kext(compiled, recursive, log)
    elif target.is_file():
        log.step("Scanning single file target")
        result = run_yara(compiled, target, recursive=False, log)
        if result.returncode not in (0, 1):
            raise RuntimeError(result.stderr.strip() or f"yara exited with code {result.returncode}")
        matches = parse_matches(result.stdout)
        stderr = result.stderr
    else:
        result = run_yara(compiled, target, recursive, log)
        if result.returncode not in (0, 1):
            raise RuntimeError(result.stderr.strip() or f"yara exited with code {result.returncode}")
        matches = parse_matches(result.stdout)
        stderr = result.stderr

    log.step(f"Scan complete: {len(matches)} match(es)")
    if stderr.strip():
        log.step("YARA reported warnings on stderr")

    for rule, filepath in matches:
        log.flag(f"{filepath} — rule `{rule}`")

    flagged_paths = sorted({filepath for _, filepath in matches})
    flagged_csv_path = flagged_csv or (
        file_list.parent / "flagged.csv" if file_list is not None else ROOT / "tmp" / "flagged.csv"
    )

    if flagged_paths:
        updated = record_flagged(flagged_paths, TOOL_NAME, csv_path=flagged_csv_path)
        log.step(f"Updated {updated} path(s) in {flagged_csv_path}")

    report = format_report(
        target=target,
        config=settings,
        rule_count=rule_count,
        yara_version=yara_version(),
        matches=matches,
        stderr=stderr,
    )

    log.step(f"Writing report to {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(report, encoding="utf-8")
