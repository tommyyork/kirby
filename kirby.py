#!/usr/bin/env python3
"""Orchestrate malware scan modules against a mounted target directory."""

from __future__ import annotations

import argparse
import importlib.util
import sys
from pathlib import Path
from typing import Literal

from kirby_flagged import FLAGGED_CSV_PATH, backfill_flagged_hashes, prepare_analysis_flagged_csv
from kirby_index import ALL_FILES_META_PATH, ALL_FILES_PATH, ensure_file_list
from kirby_kext import KEXT_TARGET, ensure_kext_file_list, is_kext_target
from kirby_log import KirbyLogger
from kirby_target import is_analysis_target, is_disk_image_or_device, is_mount_table_source


ROOT = Path(__file__).resolve().parent
MODULES_DIR = ROOT / "modules"
SCAN_MODULES_DIR = MODULES_DIR / "scan"
ANALYSIS_MODULES_DIR = MODULES_DIR / "analysis"
DEFAULT_OUTPUT_DIR = ROOT / "output"
ModuleKind = Literal["scan", "analysis"]


def normalize_module_name(name: str) -> str:
    return name.strip().lower()


def resolve_module_dir(name: str, kind: ModuleKind) -> Path:
    base = SCAN_MODULES_DIR if kind == "scan" else ANALYSIS_MODULES_DIR
    module_dir = base / normalize_module_name(name)
    if not module_dir.is_dir():
        label = "scan module" if kind == "scan" else "analysis module"
        raise FileNotFoundError(f"{label} directory not found: {module_dir}")
    return module_dir


def resolve_config_path(module_dir: Path) -> Path:
    config_path = module_dir / f"{module_dir.name}.conf"
    if not config_path.is_file():
        raise FileNotFoundError(f"Module config not found: {config_path}")
    return config_path


def load_module_main(module_dir: Path):
    main_path = module_dir / "main.py"
    if not main_path.is_file():
        raise FileNotFoundError(f"Module entrypoint not found: {main_path}")

    spec = importlib.util.spec_from_file_location(
        f"kirby_module_{module_dir.name}",
        main_path,
    )
    if spec is None or spec.loader is None:
        raise ImportError(f"Unable to load module: {main_path}")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    run = getattr(module, "run", None)
    if run is None or not callable(run):
        raise AttributeError(f"{main_path} must define a callable run() function")

    return run


def parse_module_list(raw: str) -> list[str]:
    modules = [part.strip() for part in raw.split(",") if part.strip()]
    if not modules:
        raise argparse.ArgumentTypeError("At least one module must be specified")
    return modules


def run_module(
    name: str,
    kind: ModuleKind,
    target: Path | None,
    output_dir: Path,
    verbose: bool,
    *,
    flagged_csv: Path | None = None,
) -> Path:
    log = KirbyLogger(verbose, prefix=normalize_module_name(name))
    module_dir = resolve_module_dir(name, kind)
    config_path = resolve_config_path(module_dir)
    output_path = output_dir / f"{module_dir.name}.md"
    run = load_module_main(module_dir)

    log.step(f"Loading {kind} module from {module_dir}")
    log.step(f"Using config {config_path}")
    log.step(f"Writing report to {output_path}")

    kwargs: dict[str, object] = {
        "target": target,
        "output": output_path,
        "config": config_path,
        "verbose": verbose,
    }
    if kind == "analysis" and flagged_csv is not None:
        kwargs["flagged_csv"] = flagged_csv

    run(**kwargs)

    return output_path


def log_arguments(args: argparse.Namespace, log: KirbyLogger) -> None:
    log.step("Arguments:")
    for key, value in sorted(vars(args).items()):
        log.step(f"  {key} = {value!r}")


def analysis_modules_without_target() -> frozenset[str]:
    return frozenset({"virustotal", "signatures"})


def analysis_modules_require_target(analysis_modules: list[str]) -> bool:
    optional = analysis_modules_without_target()
    return any(normalize_module_name(name) not in optional for name in analysis_modules)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run scan and analysis modules against a mounted BitLocker directory.",
    )
    parser.add_argument(
        "-t",
        "--target",
        required=False,
        type=Path,
        help="Scan target: mount point directory, disk image file, or block device (e.g. /Volumes/bitlocker, /dev/disk4). Not required with -kext. Optional for -a virustotal or -a signatures when using tmp/flagged.csv; when provided, analysis modules only process flagged paths under the target.",
    )
    parser.add_argument(
        "-kext",
        action="store_true",
        help="Special target: enumerate installed kernel extensions on this Mac and pass them to scan engines via tmp/all_files.",
    )
    parser.add_argument(
        "-e",
        "--engines",
        type=parse_module_list,
        help="Comma-separated scan module names (e.g. Yara,ClamAV,oletools)",
    )
    parser.add_argument(
        "-a",
        "--analysis",
        type=parse_module_list,
        help="Comma-separated analysis module names (e.g. virustotal)",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help=f"Output directory for markdown reports (default: {DEFAULT_OUTPUT_DIR})",
    )
    parser.add_argument(
        "-s",
        "--silent",
        action="store_true",
        help="Suppress detailed progress output and module progress bars",
    )
    return parser


def validate_target(path: Path, *, scan_modules: list[str]) -> None:
    if scan_modules:
        if not path.is_dir():
            raise argparse.ArgumentTypeError(f"Scan target must be a directory: {path}")
        return

    if is_analysis_target(path):
        return

    raise argparse.ArgumentTypeError(
        f"Target must be a mount point, disk image file, or block device: {path}"
    )


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    verbose = not args.silent
    log = KirbyLogger(verbose)

    if not args.engines and not args.analysis:
        parser.error("At least one of -e (scan modules) or -a (analysis modules) is required")

    scan_modules = args.engines or []
    analysis_modules = args.analysis or []

    if args.kext and args.target is not None:
        parser.error("-kext cannot be combined with -t/--target")

    target: Path | None
    if args.kext:
        target = KEXT_TARGET
    elif args.target is not None:
        target = args.target.resolve(strict=False)
    else:
        target = None

    if target is None:
        if scan_modules:
            parser.error("-t/--target or -kext is required when running scan modules")
        if analysis_modules_require_target(analysis_modules):
            parser.error("-t/--target is required for the selected analysis module(s)")
        print(
            f"[kirby] No target argument was provided; using previous results in "
            f"{FLAGGED_CSV_PATH} for analysis."
        )
    elif not is_kext_target(target):
        try:
            validate_target(target, scan_modules=scan_modules)
        except argparse.ArgumentTypeError as exc:
            parser.error(str(exc))

    output_dir = args.output.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    log.step("Starting kirby")
    log_arguments(args, log)

    if is_kext_target(target):
        log.step("Resolved target: macOS kernel extensions (-kext)")
    elif target is not None:
        log.step(f"Resolved target: {target}")
    else:
        log.step(f"No target provided; using flagged file list at {FLAGGED_CSV_PATH}")
    log.step(f"Output directory: {output_dir}")
    if scan_modules:
        log.step(f"Scan modules: {', '.join(scan_modules)}")
    if analysis_modules:
        log.step(f"Analysis modules: {', '.join(analysis_modules)}")

    if scan_modules:
        if is_kext_target(target):
            file_count = ensure_kext_file_list(ALL_FILES_PATH, ALL_FILES_META_PATH, log)
        else:
            file_count = ensure_file_list(target, ALL_FILES_PATH, ALL_FILES_META_PATH, log)
        log.step(f"File inventory ready ({file_count} paths)")

    for module in scan_modules:
        log.step(f"Running scan module: {module}")
        try:
            output_path = run_module(module, "scan", target, output_dir, verbose)
        except (FileNotFoundError, ImportError, AttributeError, TypeError, RuntimeError) as exc:
            print(f"Error running scan module {module}: {exc}", file=sys.stderr)
            return 1

        print(f"[{module}] wrote {output_path}")
        log.step(f"Finished scan module: {module}")

    if analysis_modules:
        backfilled = backfill_flagged_hashes(FLAGGED_CSV_PATH)
        if backfilled:
            log.step(f"Backfilled {backfilled} SHA-256 hash(es) in {FLAGGED_CSV_PATH}")

        analysis_flagged_csv, scoped_count, total_count = prepare_analysis_flagged_csv(target)
        if target is None:
            log.step(
                f"Analysis flagged scope: all {total_count} path(s) from {FLAGGED_CSV_PATH}"
            )
        else:
            log.step(
                f"Analysis flagged scope: {scoped_count} of {total_count} path(s) under {target}"
            )
            log.step(f"Using scoped flagged list at {analysis_flagged_csv}")

    for module in analysis_modules:
        log.step(f"Running analysis module: {module}")
        try:
            output_path = run_module(
                module,
                "analysis",
                target,
                output_dir,
                verbose,
                flagged_csv=analysis_flagged_csv,
            )
        except (FileNotFoundError, ImportError, AttributeError, TypeError, RuntimeError) as exc:
            print(f"Error running analysis module {module}: {exc}", file=sys.stderr)
            return 1

        print(f"[{module}] wrote {output_path}")
        log.step(f"Finished analysis module: {module}")

    log.step("All modules completed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
