"""Helpers for Kirby volume cache integration tests."""

from __future__ import annotations

import json
import re
import shutil
import sys
from dataclasses import dataclass
from io import StringIO
from pathlib import Path

from kirby_index import (
    count_indexed_paths,
    fingerprint_identity,
    inventory_paths,
    volume_fingerprint,
)

CACHE_NAMESPACE = "cache"
REUSE_MESSAGE = "volume unchanged, reusing cached inventory"
FRESH_INDEX_PATTERN = re.compile(
    r"\[kirby\] indexed \d+ path\(s\); published",
)


@dataclass(frozen=True)
class CachePaths:
    namespace: str
    mount: Path
    output_root: Path
    tmp_root: Path

    @property
    def tmp_dir(self) -> Path:
        return self.tmp_root / self.namespace

    @property
    def output_dir(self) -> Path:
        return self.output_root / self.namespace

    @property
    def all_files(self) -> Path:
        return self.tmp_dir / "all_files"

    @property
    def all_files_meta(self) -> Path:
        return self.tmp_dir / "all_files.meta"

    def volume_cache_files(self) -> tuple[Path, Path, Path]:
        identity = fingerprint_identity(volume_fingerprint(self.mount))
        return inventory_paths(identity)


def clear_tmp_namespace(paths: CachePaths) -> None:
    if paths.tmp_dir.exists():
        shutil.rmtree(paths.tmp_dir)


def clear_volume_cache_for_mount(mount: Path) -> None:
    from kirby_index import clear_volume_cache
    from kirby_log import KirbyLogger

    clear_volume_cache(mount, KirbyLogger(verbose=False))


def volume_cache_count(paths: CachePaths) -> int:
    cache_files, _, _ = paths.volume_cache_files()
    if not cache_files.is_file():
        return 0
    return count_indexed_paths(cache_files)


def load_tmp_meta(paths: CachePaths) -> dict:
    assert paths.all_files_meta.is_file(), "tmp all_files.meta is missing"
    return json.loads(paths.all_files_meta.read_text(encoding="utf-8"))


def run_kirby_capture(
    paths: CachePaths,
    *,
    engines: str = "yara",
    clear_cache: bool = False,
    top: int | None = None,
) -> tuple[int, str]:
    import kirby

    argv: list[str] = [
        "-t",
        str(paths.mount),
        "-n",
        paths.namespace,
        "-o",
        str(paths.output_root),
        "-s",
        "-e",
        engines,
    ]
    if clear_cache:
        argv.append("--clear-cache")
    if top is not None:
        argv.extend(["-top", str(top)])

    stdout = StringIO()
    stderr = StringIO()
    old_stdout, old_stderr = sys.stdout, sys.stderr
    try:
        sys.stdout = stdout
        sys.stderr = stderr
        exit_code = kirby.main(argv)
    finally:
        sys.stdout, sys.stderr = old_stdout, old_stderr

    return exit_code, stdout.getvalue() + stderr.getvalue()


def assert_indexed(output: str) -> None:
    assert FRESH_INDEX_PATTERN.search(output), (
        f"Expected fresh indexing output, got: {output!r}"
    )
    assert REUSE_MESSAGE not in output, (
        f"Did not expect cache reuse during indexing, got: {output!r}"
    )


def assert_cache_reused(output: str) -> None:
    assert REUSE_MESSAGE in output, (
        f"Expected cache reuse output containing {REUSE_MESSAGE!r}, got: {output!r}"
    )
    assert not FRESH_INDEX_PATTERN.search(output), (
        f"Did not expect fresh indexing output, got: {output!r}"
    )
