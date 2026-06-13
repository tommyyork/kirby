"""Per-target working paths under tmp/ and output/."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent
TMP_ROOT = ROOT / "tmp"
DEFAULT_OUTPUT_DIR = ROOT / "output"


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

    def output_dir(self, base: Path = DEFAULT_OUTPUT_DIR) -> Path:
        return base / self.name

    def ensure_tmp_dir(self) -> Path:
        self.tmp_dir.mkdir(parents=True, exist_ok=True)
        return self.tmp_dir


def target_paths(name: str) -> TargetPaths:
    return TargetPaths(name=name)
