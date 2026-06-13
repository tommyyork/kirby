#!/usr/bin/env python3
"""Orchestrate malware scan modules against a mounted target directory."""

from __future__ import annotations

import argparse
import importlib.util
import sys
from pathlib import Path
from typing import Literal

from kirby_flagged import backfill_flagged_hashes, normalize_flagged_csv, prepare_analysis_flagged_csv
from kirby_index import ensure_file_list, ensure_single_file_list, count_indexed_paths
from kirby_kext import KEXT_TARGET, append_kext_to_inventory, ensure_kext_file_list, is_kext_target
from kirby_log import KirbyLogger
from kirby_paths import DEFAULT_NAMESPACE, target_paths
from kirby_target import is_analysis_target, is_disk_image_or_device, is_mount_table_source, is_regular_file_target


ROOT = Path(__file__).resolve().parent
MODULES_DIR = ROOT / "modules"
SCAN_MODULES_DIR = MODULES_DIR / "scan"
ANALYSIS_MODULES_DIR = MODULES_DIR / "analysis"
RESCUE_MODULES_DIR = MODULES_DIR / "rescue"
DEFAULT_OUTPUT_DIR = ROOT / "output"
ModuleKind = Literal["scan", "analysis", "rescue"]

MODULE_ALIASES: dict[str, str] = {
    "die": "detect-it-easy",
}


def normalize_module_name(name: str) -> str:
    cleaned = name.strip().lower()
    return MODULE_ALIASES.get(cleaned, cleaned)


def resolve_module_dir(name: str, kind: ModuleKind) -> Path:
    if kind == "scan":
        base = SCAN_MODULES_DIR
    elif kind == "analysis":
        base = ANALYSIS_MODULES_DIR
    else:
        base = RESCUE_MODULES_DIR
    module_dir = base / normalize_module_name(name)
    if not module_dir.is_dir():
        labels = {
            "scan": "scan module",
            "analysis": "analysis module",
            "rescue": "rescue module",
        }
        raise FileNotFoundError(f"{labels[kind]} directory not found: {module_dir}")
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
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)

    run = getattr(module, "run", None)
    if run is None or not callable(run):
        raise AttributeError(f"{main_path} must define a callable run() function")

    return run


def parse_module_list(raw: str) -> list[str]:
    modules = [
        normalize_module_name(part)
        for part in raw.split(",")
        if part.strip()
    ]
    if not modules:
        raise argparse.ArgumentTypeError("At least one module must be specified")
    return modules


def validate_target_name(name: str) -> str:
    cleaned = name.strip()
    if not cleaned:
        raise argparse.ArgumentTypeError("Target name cannot be empty")
    if "/" in cleaned or "\\" in cleaned or cleaned in {".", ".."}:
        raise argparse.ArgumentTypeError(
            f"Target name must be a single directory name, not a path: {name!r}"
        )
    return cleaned


def run_module(
    name: str,
    kind: ModuleKind,
    target: Path | None,
    output_dir: Path,
    verbose: bool,
    *,
    flagged_csv: Path | None = None,
    file_list: Path | None = None,
    hashes_output: Path | None = None,
    include_kext: bool = False,
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
    if kind in {"analysis", "rescue"} and flagged_csv is not None:
        kwargs["flagged_csv"] = flagged_csv
    if file_list is not None:
        kwargs["file_list"] = file_list
    if hashes_output is not None:
        kwargs["hashes_output"] = hashes_output
    if include_kext:
        kwargs["include_kext"] = include_kext

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
        help=(
            "Scan target: mount point directory, specific file path, disk image file, or "
            "block device (e.g. /Volumes/bitlocker, /Volumes/Windows/Users/jane/file.exe, "
            "/dev/disk4). Optional with -kext to also scan local kernel extensions. "
            "Optional for -a virustotal or -a signatures when using tmp/<name>/flagged.csv; "
            "when provided, analysis modules only process flagged paths under the target."
        ),
    )
    parser.add_argument(
        "-kext",
        action="store_true",
        help=(
            "Include installed kernel extensions on this Mac. With -t, scans the target "
            "and kexts; without -t, scans kexts only."
        ),
    )
    parser.add_argument(
        "-e",
        "--engines",
        type=parse_module_list,
        help="Comma-separated scan module names (e.g. yara,clamav,oletools)",
    )
    parser.add_argument(
        "-a",
        "--analysis",
        type=parse_module_list,
        help="Comma-separated analysis module names (e.g. virustotal)",
    )
    parser.add_argument(
        "-r",
        "--rescue",
        type=parse_module_list,
        help="Comma-separated rescue module names (e.g. simple-rescue)",
    )
    parser.add_argument(
        "-n",
        "--name",
        type=validate_target_name,
        help=(
            "Namespace for this run. Working files go under tmp/<name>/ and markdown "
            f"reports under output/<name>/ (default: {DEFAULT_NAMESPACE!r} when omitted). "
            "Use the same name across runs to merge flagged paths and share reports."
        ),
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help=f"Base output directory for markdown reports (default: {DEFAULT_OUTPUT_DIR})",
    )
    parser.add_argument(
        "-s",
        "--silent",
        action="store_true",
        help="Suppress detailed progress output and module progress bars",
    )
    return parser


def validate_target(
    path: Path,
    *,
    scan_modules: list[str],
    rescue_modules: list[str],
) -> None:
    if is_regular_file_target(path):
        return

    if scan_modules or rescue_modules:
        if not path.is_dir():
            raise argparse.ArgumentTypeError(
                f"Scan target must be a directory or regular file: {path}"
            )
        return

    if is_analysis_target(path):
        return

    raise argparse.ArgumentTypeError(
        f"Target must be a mount point, file, disk image file, or block device: {path}"
    )


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    verbose = not args.silent
    log = KirbyLogger(verbose)

    if not args.engines and not args.analysis and not args.rescue:
        parser.error(
            "At least one of -e (scan modules), -a (analysis modules), or "
            "-r (rescue modules) is required"
        )

    scan_modules = args.engines or []
    analysis_modules = args.analysis or []
    rescue_modules = args.rescue or []
    include_kext = args.kext
    kext_only = include_kext and args.target is None

    target: Path | None
    if kext_only:
        target = KEXT_TARGET
    elif args.target is not None:
        target = args.target.resolve(strict=False)
    else:
        target = None

    if target is None:
        if scan_modules or rescue_modules:
            parser.error(
                "-t/--target or -kext is required when running scan or rescue modules"
            )
        if analysis_modules_require_target(analysis_modules):
            parser.error("-t/--target is required for the selected analysis module(s)")
        print(
            f"[kirby] No target argument was provided; analyzing "
            f"tmp/{DEFAULT_NAMESPACE}/flagged.csv (use -n to select another namespace)."
        )
    elif kext_only and rescue_modules:
        parser.error("Rescue modules require -t/--target (-kext alone is not supported)")
    elif not is_kext_target(target):
        try:
            validate_target(
                target,
                scan_modules=scan_modules,
                rescue_modules=rescue_modules,
            )
        except argparse.ArgumentTypeError as exc:
            parser.error(str(exc))

    target_name = args.name if args.name is not None else DEFAULT_NAMESPACE
    paths = target_paths(target_name)
    paths.ensure_tmp_dir()
    normalized_flagged = normalize_flagged_csv(paths.flagged_csv)
    if normalized_flagged:
        log.step(f"Normalized tool names for {normalized_flagged} path(s) in {paths.flagged_csv}")
    output_dir = (args.output / target_name).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    log.step("Starting kirby")
    log_arguments(args, log)

    if is_kext_target(target):
        log.step("Resolved target: macOS kernel extensions (-kext)")
    elif include_kext and target is not None:
        log.step(f"Resolved target: {target} plus macOS kernel extensions (-kext)")
    elif target is not None and is_regular_file_target(target):
        log.step(f"Resolved target: single file {target}")
    elif target is not None:
        log.step(f"Resolved target: {target}")
    else:
        log.step(f"No target provided; using flagged file list at {paths.flagged_csv}")
    log.step(f"Target name: {target_name}")
    log.step(f"Working directory: {paths.tmp_dir}")
    log.step(f"Output directory: {output_dir}")
    if scan_modules:
        log.step(f"Scan modules: {', '.join(scan_modules)}")
    if analysis_modules:
        log.step(f"Analysis modules: {', '.join(analysis_modules)}")
    if rescue_modules:
        log.step(f"Rescue modules: {', '.join(rescue_modules)}")

    if scan_modules or rescue_modules:
        if is_kext_target(target):
            file_count = ensure_kext_file_list(
                paths.all_files,
                paths.all_files_meta,
                paths.sha256_hashes,
                log,
            )
        elif is_regular_file_target(target):
            file_count = ensure_single_file_list(
                target,
                paths.all_files,
                paths.all_files_meta,
                paths.sha256_hashes,
                log,
            )
        else:
            file_count = ensure_file_list(
                target,
                paths.all_files,
                paths.all_files_meta,
                paths.sha256_hashes,
                log,
            )
        if include_kext and not is_kext_target(target):
            append_kext_to_inventory(
                paths.all_files,
                paths.sha256_hashes,
                log,
            )
        file_count = count_indexed_paths(paths.all_files)
        log.step(f"File inventory ready ({file_count} paths)")

    for module in scan_modules:
        log.step(f"Running scan module: {module}")
        try:
            output_path = run_module(
                module,
                "scan",
                target,
                output_dir,
                verbose,
                flagged_csv=paths.flagged_csv,
                file_list=paths.all_files,
                include_kext=include_kext and not is_kext_target(target),
            )
        except (FileNotFoundError, ImportError, AttributeError, TypeError, RuntimeError) as exc:
            print(f"Error running scan module {module}: {exc}", file=sys.stderr)
            return 1

        print(f"[{module}] wrote {output_path}")
        log.step(f"Finished scan module: {module}")

    for module in rescue_modules:
        log.step(f"Running rescue module: {module}")
        try:
            output_path = run_module(
                module,
                "rescue",
                target,
                output_dir,
                verbose,
                flagged_csv=paths.flagged_csv,
                file_list=paths.all_files,
            )
        except (FileNotFoundError, ImportError, AttributeError, TypeError, RuntimeError) as exc:
            print(f"Error running rescue module {module}: {exc}", file=sys.stderr)
            return 1

        print(f"[{module}] wrote {output_path}")
        log.step(f"Finished rescue module: {module}")

    if analysis_modules:
        backfilled = backfill_flagged_hashes(
            paths.flagged_csv,
            hashes_path=paths.sha256_hashes,
        )
        if backfilled:
            log.step(f"Backfilled {backfilled} SHA-256 hash(es) in {paths.flagged_csv}")

        analysis_flagged_csv, scoped_count, total_count = prepare_analysis_flagged_csv(
            target,
            source_csv=paths.flagged_csv,
            scoped_csv=paths.flagged_scoped_csv,
            include_kext=include_kext and not is_kext_target(target),
        )
        if target is None:
            log.step(
                f"Analysis flagged scope: all {total_count} path(s) from {paths.flagged_csv}"
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
                hashes_output=paths.virustotal_hashes,
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
