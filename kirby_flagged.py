"""Shared flagged-file registry for kirby scan modules."""

from __future__ import annotations

import csv
from collections.abc import Iterable
from pathlib import Path

from kirby_index import load_hash_cache, lookup_sha256
from kirby_kext import is_kext_path, is_kext_target
from kirby_target import resolve_flagged_filter_root

ROOT = Path(__file__).resolve().parent
FLAGGED_CSV_PATH = ROOT / "tmp" / "flagged.csv"
FLAGGED_SCOPED_CSV_PATH = ROOT / "tmp" / "flagged-scoped.csv"
FlaggedEntry = tuple[list[str], str]


def _normalize_path(path: str | Path) -> str:
    return str(Path(path).resolve())


def load_flagged(csv_path: Path = FLAGGED_CSV_PATH) -> dict[str, FlaggedEntry]:
    if not csv_path.is_file():
        return {}

    flagged: dict[str, FlaggedEntry] = {}
    with csv_path.open(newline="", encoding="utf-8") as handle:
        for row in csv.reader(handle):
            if len(row) < 2:
                continue
            path = row[0].strip()
            tools = [tool.strip() for tool in row[1].split(",") if tool.strip()]
            sha256 = row[2].strip() if len(row) >= 3 else ""
            if path:
                flagged[path] = (tools, sha256)
    return flagged


def save_flagged(flagged: dict[str, FlaggedEntry], csv_path: Path = FLAGGED_CSV_PATH) -> None:
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        for path, (tools, sha256) in flagged.items():
            writer.writerow([path, ",".join(tools), sha256])


def record_flagged(
    paths: Iterable[str | Path],
    tool: str,
    *,
    csv_path: Path = FLAGGED_CSV_PATH,
    normalize: bool = True,
) -> int:
    """Register files flagged by a scan tool.

    If a path is already present, append the tool name to its tool list when
    missing. Returns the number of paths that were added or updated.

    When normalize is False, paths are stored verbatim (for registry key paths)
    and no SHA-256 hash is recorded.
    """
    normalized_tool = tool.strip()
    if not normalized_tool:
        raise ValueError("tool name must not be empty")

    hash_cache = load_hash_cache() if normalize else {}
    flagged = load_flagged(csv_path)
    updated = 0

    for raw_path in paths:
        path = _normalize_path(raw_path) if normalize else str(raw_path).strip()
        if not path:
            continue

        tools, sha256 = flagged.get(path, ([], ""))
        if normalize and not sha256:
            sha256 = lookup_sha256(path, hash_cache)

        if normalized_tool in tools:
            if sha256 and flagged.get(path, ([], ""))[1] != sha256:
                flagged[path] = (tools, sha256)
                updated += 1
            continue

        tools.append(normalized_tool)
        flagged[path] = (tools, sha256)
        updated += 1

    if updated:
        save_flagged(flagged, csv_path)

    return updated


def backfill_flagged_hashes(csv_path: Path = FLAGGED_CSV_PATH) -> int:
    """Fill missing SHA-256 values in flagged.csv from tmp/sha256_hashes."""
    hash_cache = load_hash_cache()
    flagged = load_flagged(csv_path)
    updated = 0

    for path, (tools, sha256) in flagged.items():
        if sha256:
            continue
        if not Path(path).is_file():
            continue
        digest = lookup_sha256(path, hash_cache)
        if not digest:
            continue
        flagged[path] = (tools, digest)
        updated += 1

    if updated:
        save_flagged(flagged, csv_path)

    return updated


def is_flagged_path_under_target(path_str: str, target_root: Path) -> bool:
    """Return True when a flagged filesystem path lies under target_root."""
    if not path_str.startswith("/"):
        return False

    try:
        path = Path(path_str).resolve(strict=False)
        target = target_root.resolve(strict=False)
        return path == target or path.is_relative_to(target)
    except (OSError, ValueError):
        return False


def filter_flagged_for_target(
    flagged: dict[str, FlaggedEntry],
    target: Path | None,
) -> dict[str, FlaggedEntry]:
    """Keep only filesystem paths that fall under the provided target."""
    if target is None:
        return flagged

    if is_kext_target(target):
        return {
            path: entry
            for path, entry in flagged.items()
            if is_kext_path(path)
        }

    target_root = resolve_flagged_filter_root(target)
    return {
        path: entry
        for path, entry in flagged.items()
        if is_flagged_path_under_target(path, target_root)
    }


def prepare_analysis_flagged_csv(
    target: Path | None,
    *,
    source_csv: Path = FLAGGED_CSV_PATH,
    scoped_csv: Path = FLAGGED_SCOPED_CSV_PATH,
) -> tuple[Path, int, int]:
    """Return the flagged CSV analysis modules should read.

    When target is None, returns the full source list. Otherwise writes a scoped
    CSV containing only paths under the target and returns that path.
    """
    flagged = load_flagged(source_csv)
    total = len(flagged)
    if target is None:
        return source_csv, total, total

    filtered = filter_flagged_for_target(flagged, target)
    scoped_csv.parent.mkdir(parents=True, exist_ok=True)
    save_flagged(filtered, scoped_csv)
    return scoped_csv, len(filtered), total
