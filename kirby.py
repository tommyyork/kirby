#!/usr/bin/env python3
"""Orchestrate malware scan modules against a mounted target directory."""

from __future__ import annotations

import argparse
import importlib.util
import sys
from pathlib import Path
from typing import Literal

from kirby_flagged import backfill_flagged_hashes, normalize_flagged_csv, prepare_analysis_flagged_csv
from kirby_index import (
    clear_volume_cache,
    count_indexed_paths,
    ensure_file_list,
    ensure_single_file_list,
    find_cached_paths,
    limit_inventory,
)
from kirby_kext import KEXT_TARGET, append_kext_to_inventory, ensure_kext_file_list, is_kext_target
from kirby_file_list import (
    WorkingList,
    is_file_list_target,
    materialize_plain_list_for_analysis,
    resolve_working_list,
)
from kirby_log import KirbyLogger
from kirby_module_targets import (
    ModuleKind as TargetModuleKind,
    TargetKind,
    build_target_compatibility_report,
    format_target_compatibility_report,
    load_module_targets,
)
from kirby_paths import DEFAULT_NAMESPACE, target_paths
from kirby_target import (
    classify_target_kind,
    is_analysis_target,
    is_disk_image_or_device,
    is_mount_table_source,
    is_regular_file_target,
)


ROOT = Path(__file__).resolve().parent
MODULES_DIR = ROOT / "modules"
SCAN_MODULES_DIR = MODULES_DIR / "scan"
ANALYSIS_MODULES_DIR = MODULES_DIR / "analysis"
RESCUE_MODULES_DIR = MODULES_DIR / "rescue"
DEFAULT_OUTPUT_DIR = ROOT / "output"
ModuleKind = Literal["scan", "analysis", "rescue"]

EXIT_SUCCESS = 0
EXIT_MODULE_FAILURE = 1
EXIT_TARGET_MISMATCH = 2

MODULE_ALIASES: dict[str, str] = {
    "die": "detect-it-easy",
}

INVENTORY_OPTIONAL_SCAN = frozenset({"sleuthkit-ntfs"})


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


def parse_top_n(value: str) -> int:
    try:
        count = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"-top must be a positive integer, not {value!r}") from exc
    if count < 1:
        raise argparse.ArgumentTypeError("-top must be a positive integer")
    return count


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
    force_errors: bool = False,
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
    kwargs["force_errors"] = force_errors

    run(**kwargs)

    return output_path


def collect_requested_modules(
    scan_modules: list[str],
    analysis_modules: list[str],
    rescue_modules: list[str],
) -> list[tuple[str, TargetModuleKind]]:
    requested: list[tuple[str, TargetModuleKind]] = []
    for name in scan_modules:
        requested.append((normalize_module_name(name), "scan"))
    for name in rescue_modules:
        requested.append((normalize_module_name(name), "rescue"))
    for name in analysis_modules:
        requested.append((normalize_module_name(name), "analysis"))
    return requested


def load_module_supported_targets(
    module_name: str,
    kind: TargetModuleKind,
) -> frozenset[TargetKind]:
    module_dir = resolve_module_dir(module_name, kind)
    config_path = resolve_config_path(module_dir)
    return load_module_targets(config_path)


def log_arguments(args: argparse.Namespace, log: KirbyLogger) -> None:
    log.step("Arguments:")
    for key, value in sorted(vars(args).items()):
        log.step(f"  {key} = {value!r}")


def analysis_modules_without_target() -> frozenset[str]:
    return frozenset({"virustotal", "signatures"})


def analysis_modules_require_target(analysis_modules: list[str]) -> bool:
    del analysis_modules
    return False


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
            "Scan target: mount point directory, specific file path, CSV file list, disk image file, or "
            "block device (e.g. /Volumes/bitlocker, /Volumes/Windows/Users/jane/file.exe, "
            "tmp/<name>/paths.csv, /dev/disk4). Optional with -kext to also scan local kernel extensions. "
            "Optional for -a when tmp/<name>/flagged.csv or -t <paths.csv> is populated; "
            "when a directory or file target is provided, analysis modules scope flagged paths under it."
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
        "-top",
        type=parse_top_n,
        metavar="N",
        help=(
            "Process only the first N files: stop indexing after N paths, then scan, "
            "analyze, and rescue within that limited set (useful for smoke tests)"
        ),
    )
    parser.add_argument(
        "-s",
        "--silent",
        action="store_true",
        help="Suppress detailed progress output and module progress bars",
    )
    parser.add_argument(
        "--clear-cache",
        action="store_true",
        help=(
            "Delete the persistent volume inventory cache for the -t target before indexing "
            "(requires -t/--target)"
        ),
    )
    parser.add_argument(
        "-find",
        metavar="REGEX",
        help=(
            "Search cached file inventories for paths matching REGEX. Simple * and ? "
            "wildcards are supported. Use with -n and/or -t; without -t, -n searches all "
            "volume caches plus tmp/<name>/all_files."
        ),
    )
    parser.add_argument(
        "--force-errors",
        action="store_true",
        help=(
            "Continue when a module hits serious external-tool errors (non-zero exit codes, "
            "fatal stderr, API failures). By default Kirby stops the run and exits with an error."
        ),
    )
    return parser


def scan_allows_device_target(scan_modules: list[str]) -> bool:
    return any(normalize_module_name(name) in INVENTORY_OPTIONAL_SCAN for name in scan_modules)


def needs_file_inventory(
    target: Path | None,
    scan_modules: list[str],
    rescue_modules: list[str],
) -> bool:
    if target is not None and is_file_list_target(target):
        return False
    if rescue_modules:
        return True
    if not scan_modules:
        return False
    optional_only = all(
        normalize_module_name(name) in INVENTORY_OPTIONAL_SCAN for name in scan_modules
    )
    if optional_only:
        return False
    if target is not None and is_disk_image_or_device(target):
        return True
    return True


def validate_target(
    path: Path,
    *,
    scan_modules: list[str],
    rescue_modules: list[str],
) -> None:
    if is_file_list_target(path):
        return

    if is_regular_file_target(path):
        return

    if scan_modules or rescue_modules:
        if path.is_dir():
            return
        if scan_allows_device_target(scan_modules) and is_disk_image_or_device(path):
            return
        raise argparse.ArgumentTypeError(
            f"Scan target must be a directory, regular file, or block device/image: {path}"
        )

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

    if not args.engines and not args.analysis and not args.rescue and not args.find:
        parser.error(
            "At least one of -e (scan modules), -a (analysis modules), "
            "-r (rescue modules), or -find is required"
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
        if not args.find and not analysis_modules:
            print(
                f"[kirby] No target argument was provided; analyzing "
                f"tmp/{DEFAULT_NAMESPACE}/flagged.csv (use -n to select another namespace)."
            )
    elif kext_only and rescue_modules:
        parser.error("Rescue modules require -t/--target (-kext alone is not supported)")
    elif not is_kext_target(target) and not args.find:
        try:
            validate_target(
                target,
                scan_modules=scan_modules,
                rescue_modules=rescue_modules,
            )
        except argparse.ArgumentTypeError as exc:
            parser.error(str(exc))

    if args.clear_cache:
        if target is None or is_kext_target(target):
            parser.error("--clear-cache requires -t/--target pointing at a mounted volume or file")
        clear_volume_cache(target, log)

    if args.find:
        if target is None and args.name is None:
            parser.error("-find requires -n/--name and/or -t/--target")

    target_name = args.name if args.name is not None else DEFAULT_NAMESPACE
    paths = target_paths(target_name)

    if args.find:
        tmp_files = paths.all_files if paths.all_files.is_file() else None
        matches = find_cached_paths(
            args.find,
            target=target,
            tmp_files_path=tmp_files,
            search_all_caches=target is None,
            log=log,
        )
        for match in matches:
            print(match)
        if not log.verbose:
            print(f"[kirby] {len(matches)} match(es) for pattern {args.find!r}", file=sys.stderr)
        else:
            log.step(f"Found {len(matches)} match(es) for pattern {args.find!r}")
        return 0

    paths.ensure_tmp_dir()
    working_list = resolve_working_list(target, paths.flagged_csv)

    try:
        target_kind = classify_target_kind(target, kext_only=kext_only)
    except ValueError as exc:
        parser.error(str(exc))

    target_compatibility = build_target_compatibility_report(
        collect_requested_modules(scan_modules, analysis_modules, rescue_modules),
        target_kind=target_kind,
        working_list_available=working_list is not None,
        load_supported=load_module_supported_targets,
    )
    if target_compatibility.has_failures():
        print(format_target_compatibility_report(target_compatibility), file=sys.stderr)
        return EXIT_TARGET_MISMATCH

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
    elif target is not None and is_file_list_target(target):
        log.step(f"Resolved target: CSV file list {target}")
        if working_list is not None:
            log.step(
                f"File list ready ({working_list.entry_count} path(s) from {working_list.source})"
            )
    elif target is not None and is_regular_file_target(target):
        log.step(f"Resolved target: single file {target}")
    elif target is not None:
        log.step(f"Resolved target: {target}")
    else:
        if working_list is not None:
            log.step(
                f"No filesystem target provided; using {working_list.path} "
                f"({working_list.entry_count} path(s))"
            )
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
    if args.top is not None:
        log.step(f"Limiting run to first {args.top} file(s) (-top {args.top})")

    top_n = args.top
    scan_file_list = (
        target
        if target is not None and is_file_list_target(target)
        else paths.all_files
    )

    if scan_modules or rescue_modules:
        if needs_file_inventory(target, scan_modules, rescue_modules):
            if is_kext_target(target):
                file_count = ensure_kext_file_list(
                    paths.all_files,
                    paths.all_files_meta,
                    paths.sha256_hashes,
                    log,
                    top_n=top_n,
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
                hash_files = bool(scan_modules) or bool(analysis_modules)
                file_count = ensure_file_list(
                    target,
                    paths.all_files,
                    paths.all_files_meta,
                    paths.sha256_hashes,
                    log,
                    hash_files=hash_files,
                    top_n=top_n,
                )
            if include_kext and not is_kext_target(target):
                append_kext_to_inventory(
                    paths.all_files,
                    paths.sha256_hashes,
                    log,
                )
                if top_n is not None:
                    limit_inventory(
                        paths.all_files,
                        paths.sha256_hashes,
                        paths.all_files_meta,
                        top_n,
                        log,
                    )
            file_count = count_indexed_paths(paths.all_files)
            log.step(f"File inventory ready ({file_count} paths)")
        else:
            log.step("Skipping file inventory (not required for selected scan module(s))")

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
                file_list=(
                    scan_file_list
                    if is_file_list_target(target) or scan_file_list.is_file()
                    else None
                ),
                include_kext=include_kext and not is_kext_target(target),
                force_errors=args.force_errors,
            )
        except (FileNotFoundError, ImportError, AttributeError, TypeError, RuntimeError) as exc:
            print(f"Error running scan module {module}: {exc}", file=sys.stderr)
            return EXIT_MODULE_FAILURE

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
                force_errors=args.force_errors,
            )
        except (FileNotFoundError, ImportError, AttributeError, TypeError, RuntimeError) as exc:
            print(f"Error running rescue module {module}: {exc}", file=sys.stderr)
            return EXIT_MODULE_FAILURE

        print(f"[{module}] wrote {output_path}")
        log.step(f"Finished rescue module: {module}")

    if analysis_modules:
        if working_list is None:
            print(
                "Error: analysis modules require a populated file list "
                f"(pass -t <paths.csv> or ensure {paths.flagged_csv} has entries)",
                file=sys.stderr,
            )
            return EXIT_TARGET_MISMATCH

        backfilled = backfill_flagged_hashes(
            paths.flagged_csv,
            hashes_path=paths.sha256_hashes,
        )
        if backfilled:
            log.step(f"Backfilled {backfilled} SHA-256 hash(es) in {paths.flagged_csv}")

        if working_list.source == "file_list":
            if working_list.kind == "flagged":
                analysis_flagged_csv = working_list.path
                scoped_count = working_list.entry_count
                total_count = scoped_count
            else:
                analysis_flagged_csv = materialize_plain_list_for_analysis(
                    working_list.path,
                    paths.flagged_scoped_csv,
                )
                scoped_count = working_list.entry_count
                total_count = scoped_count
            log.step(
                f"Analysis file list: {scoped_count} path(s) from {working_list.path}"
            )
        else:
            analysis_flagged_csv, scoped_count, total_count = prepare_analysis_flagged_csv(
                target,
                source_csv=paths.flagged_csv,
                scoped_csv=paths.flagged_scoped_csv,
                include_kext=include_kext and not is_kext_target(target),
                top_n=top_n,
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
                force_errors=args.force_errors,
            )
        except (FileNotFoundError, ImportError, AttributeError, TypeError, RuntimeError) as exc:
            print(f"Error running analysis module {module}: {exc}", file=sys.stderr)
            return EXIT_MODULE_FAILURE

        print(f"[{module}] wrote {output_path}")
        log.step(f"Finished analysis module: {module}")

    log.step("All modules completed")
    return EXIT_SUCCESS


if __name__ == "__main__":
    raise SystemExit(main())
