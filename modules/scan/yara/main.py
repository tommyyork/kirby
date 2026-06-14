"""YARA scan module using Neo23x0's signature-base ruleset."""

from __future__ import annotations

import configparser
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from kirby_flagged import record_flagged
from kirby_kext import is_kext_target, kext_search_roots
from kirby_log import KirbyLogger
from kirby_report import format_scan_report_header
from kirby_file_list import read_scan_paths, uses_explicit_file_list
from kirby_target import resolve_flagged_filter_root
from kirby_tool_errors import check_subprocess, serious_stderr_lines

TOOL_NAME = "yara"
SCAN_BATCH_SIZE = 250

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


def yara_binary() -> str:
    yara = shutil.which("yara")
    if yara is None:
        raise RuntimeError("yara not found; install YARA (e.g. brew install yara)")
    return yara


def read_file_list(path: Path, log: KirbyLogger) -> list[Path]:
    if not path.is_file():
        raise FileNotFoundError(f"File list not found: {path}")

    log.step(f"Reading file inventory from {path}")
    files = [Path(entry.strip()) for entry in path.read_text(encoding="utf-8").splitlines() if entry.strip()]
    log.step(f"Loaded {len(files)} paths from inventory")
    return files


def is_under_target(path: Path, target_root: Path) -> bool:
    try:
        resolved_path = path.resolve(strict=False)
        resolved_target = target_root.resolve(strict=False)
        if resolved_target.is_file():
            return resolved_path == resolved_target
        return resolved_path == resolved_target or resolved_path.is_relative_to(resolved_target)
    except (OSError, ValueError):
        return False


def filter_files_for_target(
    files: list[Path],
    target: Path,
    *,
    recursive: bool,
) -> list[Path]:
    target_root = resolve_flagged_filter_root(target)
    filtered: list[Path] = []

    for path in files:
        if not path.is_file():
            continue
        if not is_under_target(path, target_root):
            continue
        if not recursive and path.parent.resolve(strict=False) != target_root.resolve(strict=False):
            continue
        filtered.append(path)

    filtered.sort(key=lambda item: str(item).lower())
    return filtered


def walk_target_files(target: Path, *, recursive: bool) -> list[Path]:
    if target.is_file():
        return [target.resolve(strict=False)]

    if not target.is_dir():
        return []

    if recursive:
        files = [path for path in target.rglob("*") if path.is_file()]
    else:
        files = [path for path in target.iterdir() if path.is_file()]

    files.sort(key=lambda item: str(item).lower())
    return files


def collect_scan_files(
    target: Path,
    *,
    recursive: bool,
    file_list: Path | None,
    log: KirbyLogger,
) -> list[Path]:
    if uses_explicit_file_list(target, file_list):
        files = [path for path in read_scan_paths(target, log) if path.is_file()]
        files.sort(key=lambda item: str(item).lower())
        log.step(f"Selected {len(files)} file(s) from explicit file list")
        return files

    if file_list is not None and file_list.is_file() and not is_kext_target(target):
        files = filter_files_for_target(read_file_list(file_list, log), target, recursive=recursive)
        log.step(f"Selected {len(files)} file(s) from inventory for scanning")
        return files

    files = walk_target_files(target, recursive=recursive)
    log.step(f"Collected {len(files)} file(s) for scanning")
    return files


def collect_kext_scan_files(*, recursive: bool, log: KirbyLogger) -> list[Path]:
    roots = kext_search_roots()
    if not roots:
        raise RuntimeError("No kernel extension directories found on this system")

    files: list[Path] = []
    seen: set[str] = set()
    for root in roots:
        for path in walk_target_files(root, recursive=recursive):
            key = str(path.resolve(strict=False)).lower()
            if key in seen:
                continue
            seen.add(key)
            files.append(path)

    files.sort(key=lambda item: str(item).lower())
    log.step(f"Collected {len(files)} kernel extension file(s) for scanning")
    return files


def run_yara_batch(
    yara: str,
    compiled: Path,
    files: list[Path],
) -> subprocess.CompletedProcess[str]:
    # YARA 4.5+ treats extra positional args after -C as rules files, not scan
    # targets. Pass batches via --scan-list instead.
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="utf-8") as handle:
        for path in files:
            handle.write(f"{path}\n")
        scan_list = Path(handle.name)

    try:
        return subprocess.run(
            [yara, "-C", str(compiled), "--scan-list", str(scan_list)],
            capture_output=True,
            text=True,
            check=False,
        )
    finally:
        scan_list.unlink(missing_ok=True)


def run_yara_on_files(
    compiled: Path,
    files: list[Path],
    log: KirbyLogger,
    *,
    desc: str = "Scanning files",
    force_errors: bool = False,
) -> tuple[list[tuple[str, str]], str]:
    if not files:
        log.step("No files to scan")
        return [], ""

    yara = yara_binary()
    matches: list[tuple[str, str]] = []
    stderr_parts: list[str] = []
    batch: list[Path] = []
    allowed_returncodes = frozenset({0, 1})

    def process_batch(current_batch: list[Path]) -> None:
        result = run_yara_batch(yara, compiled, current_batch)
        if not check_subprocess(
            result,
            context="yara scan failed",
            allowed_returncodes=allowed_returncodes,
            force_errors=force_errors,
            warnings=stderr_parts,
        ):
            return
        matches.extend(parse_matches(result.stdout))
        stderr = (result.stderr or "").strip()
        if stderr and not serious_stderr_lines(stderr):
            stderr_parts.append(stderr)

    for filepath in log.progress(files, total=len(files), desc=desc, unit="file"):
        batch.append(filepath)
        if len(batch) < SCAN_BATCH_SIZE:
            continue

        process_batch(batch)
        batch = []

    if batch:
        process_batch(batch)

    return matches, "\n\n".join(stderr_parts)


def run_yara_kext(
    compiled: Path,
    recursive: bool,
    log: KirbyLogger,
    *,
    force_errors: bool = False,
) -> tuple[list[tuple[str, str]], str, int]:
    files = collect_kext_scan_files(recursive=recursive, log=log)
    matches, stderr = run_yara_on_files(
        compiled,
        files,
        log,
        desc="Scanning kext files",
        force_errors=force_errors,
    )
    returncode = 1 if matches else 0
    return matches, stderr, returncode


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
    include_kext: bool = False,
    force_errors: bool = False,
) -> None:
    log = KirbyLogger(verbose, prefix="yara")
    log.step(f"Loading config from {config}")
    settings = load_config(config)

    base = ensure_ruleset(settings, log)
    compiled, rule_count = ensure_compiled_rules(base, settings, log)
    recursive = settings.getboolean("yara", "recursive", fallback=True)
    log.step(f"Recursive scan: {recursive}")

    matches: list[tuple[str, str]] = []
    stderr_parts: list[str] = []

    if is_kext_target(target):
        log.step("Scanning kernel extension directories")
        kext_matches, kext_stderr, _returncode = run_yara_kext(
            compiled, recursive, log, force_errors=force_errors
        )
        matches.extend(kext_matches)
        if kext_stderr.strip():
            stderr_parts.append(kext_stderr.strip())
    else:
        scan_files = collect_scan_files(
            target,
            recursive=recursive,
            file_list=file_list,
            log=log,
        )
        target_matches, target_stderr = run_yara_on_files(
            compiled,
            scan_files,
            log,
            desc="Scanning files",
            force_errors=force_errors,
        )
        matches.extend(target_matches)
        if target_stderr.strip():
            stderr_parts.append(target_stderr.strip())

    if include_kext and not is_kext_target(target):
        log.step("Also scanning kernel extension directories")
        kext_matches, kext_stderr, _returncode = run_yara_kext(
            compiled, recursive, log, force_errors=force_errors
        )
        matches.extend(kext_matches)
        if kext_stderr.strip():
            stderr_parts.append(kext_stderr.strip())

    stderr = "\n\n".join(stderr_parts)

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
