"""Path-list targets and shared list I/O for Kirby scan/analysis modules."""

from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from kirby_target import is_file_list_target

ListKind = Literal["plain", "flagged"]
WorkingListSource = Literal["file_list", "flagged_csv"]


@dataclass(frozen=True)
class WorkingList:
    """Resolved path list that list-dependent modules should consume."""

    path: Path
    source: WorkingListSource
    kind: ListKind
    entry_count: int


class FileListSource:
    """Stub base for future list providers (remote exports, databases, etc.)."""

    def resolve(self) -> Path:
        raise NotImplementedError


class PublishedFileListSource(FileListSource):
    """Stub for lists materialized under tmp/<namespace>/."""

    def __init__(self, destination: Path) -> None:
        self.destination = destination

    def resolve(self) -> Path:
        raise NotImplementedError(
            f"PublishedFileListSource.resolve() is not implemented yet ({self.destination})"
        )


def is_file_list_target(path: Path | None) -> bool:
    """Re-export target classification for list-aware modules."""
    from kirby_target import is_file_list_target as _is_file_list_target

    return _is_file_list_target(path)


def detect_list_kind(path: Path) -> ListKind:
    """Classify a CSV target as a flagged registry or a plain path list."""
    from kirby_flagged import load_flagged

    if not path.is_file():
        raise FileNotFoundError(f"File list not found: {path}")

    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.reader(handle)
        for row in reader:
            if not row or not row[0].strip():
                continue
            if len(row) >= 2 and row[1].strip():
                return "flagged"
            return "plain"
    return "plain"


def read_path_entries(path: Path) -> list[str]:
    """Read absolute paths from a plain path list or flagged CSV."""
    from kirby_flagged import load_flagged

    if not path.is_file():
        raise FileNotFoundError(f"File list not found: {path}")

    if detect_list_kind(path) == "flagged":
        return list(load_flagged(path).keys())

    entries: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        entry = line.strip()
        if not entry or entry.startswith("#"):
            continue
        if "," in entry and not entry.startswith("/"):
            path_value, _, _remainder = entry.partition(",")
            entry = path_value.strip()
        if entry:
            entries.append(entry)
    return entries


def read_scan_paths(path: Path, log) -> list[Path]:
    """Load scan paths from an explicit list target."""
    from kirby_log import KirbyLogger

    logger: KirbyLogger = log
    logger.step(f"Reading explicit file list from {path}")
    paths = [Path(entry) for entry in read_path_entries(path)]
    logger.step(f"Loaded {len(paths)} path(s) from file list")
    return paths


def flagged_csv_has_entries(csv_path: Path) -> bool:
    from kirby_flagged import load_flagged

    return bool(load_flagged(csv_path))


def uses_explicit_file_list(target: Path, file_list: Path | None) -> bool:
    """True when modules should read paths directly from the list target."""
    if is_file_list_target(target):
        return True
    if file_list is None:
        return False
    try:
        return target.resolve(strict=False) == file_list.resolve(strict=False)
    except OSError:
        return target == file_list


def resolve_working_list(
    target: Path | None,
    flagged_csv: Path,
) -> WorkingList | None:
    """Return the populated list analysis modules can run against."""
    from kirby_flagged import load_flagged

    if target is not None and is_file_list_target(target):
        kind = detect_list_kind(target)
        entries = read_path_entries(target)
        if not entries:
            return None
        return WorkingList(
            path=target,
            source="file_list",
            kind=kind,
            entry_count=len(entries),
        )

    if flagged_csv_has_entries(flagged_csv):
        return WorkingList(
            path=flagged_csv,
            source="flagged_csv",
            kind="flagged",
            entry_count=len(load_flagged(flagged_csv)),
        )
    return None


def materialize_plain_list_for_analysis(
    source: Path,
    destination: Path,
    *,
    tool_name: str = "list",
) -> Path:
    """Write a plain path list CSV to flagged-shaped CSV for analysis modules."""
    from kirby_flagged import save_flagged

    entries = {
        path: ([tool_name], "")
        for path in read_path_entries(source)
    }
    destination.parent.mkdir(parents=True, exist_ok=True)
    save_flagged(entries, destination)
    return destination


def publish_file_list_to_tmp(
    source: Path,
    destination: Path,
    *,
    namespace: str,
) -> Path:
    """Stub for future list normalization under tmp/<namespace>/."""
    raise NotImplementedError(
        f"publish_file_list_to_tmp is not implemented yet "
        f"(source={source}, destination={destination}, namespace={namespace!r})"
    )


def merge_file_list_sources(
    *sources: FileListSource,
) -> Path:
    """Stub for future multi-source list composition."""
    raise NotImplementedError("merge_file_list_sources is not implemented yet")
