"""Per-target working paths under tmp/ and output/."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def resolve_tmp_root() -> Path:
    """Return the Kirby tmp root (override with KIRBY_TMP_ROOT for tests)."""
    override = os.environ.get("KIRBY_TMP_ROOT", "").strip()
    if override:
        path = Path(override)
        if not path.is_absolute():
            path = ROOT / path
        return path
    return ROOT / "tmp"


TMP_ROOT = resolve_tmp_root()
DEFAULT_OUTPUT_DIR = ROOT / "output"
DEFAULT_NAMESPACE = "default_namespace"


@dataclass(frozen=True)
class TargetPaths:
    name: str

    @property
    def tmp_dir(self) -> Path:
        return TMP_ROOT / self.name

    @property
    def all_files(self) -> Path:
        return self.tmp_dir / "all_files"

    @property
    def all_files_meta(self) -> Path:
        return self.tmp_dir / "all_files.meta"

    @property
    def sha256_hashes(self) -> Path:
        return self.tmp_dir / "sha256_hashes"

    @property
    def flagged_csv(self) -> Path:
        return self.tmp_dir / "flagged.csv"

    @property
    def flagged_scoped_csv(self) -> Path:
        return self.tmp_dir / "flagged-scoped.csv"

    @property
    def virustotal_hashes(self) -> Path:
        return self.tmp_dir / "virustotal-hashes"

    @property
    def file_list_csv(self) -> Path:
        return self.tmp_dir / "file-list.csv"

    def output_dir(self, base: Path = DEFAULT_OUTPUT_DIR) -> Path:
        return base / self.name

    def ensure_tmp_dir(self) -> Path:
        self.tmp_dir.mkdir(parents=True, exist_ok=True)
        return self.tmp_dir


def target_paths(name: str) -> TargetPaths:
    return TargetPaths(name=name)
