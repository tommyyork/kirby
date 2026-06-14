"""Helpers for the basics Kirby integration test suite."""

from __future__ import annotations

import io
import sys
from dataclasses import dataclass
from pathlib import Path

from kirby import EXIT_MODULE_FAILURE, EXIT_TARGET_MISMATCH, EXIT_SUCCESS

BASICS_NAMESPACE = "basics"


@dataclass(frozen=True)
class BasicsPaths:
    namespace: str
    iso: Path
    mount: Path
    output_root: Path
    tmp_root: Path

    @property
    def output_dir(self) -> Path:
        return self.output_root / self.namespace

    @property
    def tmp_dir(self) -> Path:
        return self.tmp_root / self.namespace

    @property
    def all_files(self) -> Path:
        return self.tmp_dir / "all_files"

    @property
    def all_files_meta(self) -> Path:
        return self.tmp_dir / "all_files.meta"

    @property
    def yara_report(self) -> Path:
        return self.output_dir / "yara.md"

    @property
    def clamav_report(self) -> Path:
        return self.output_dir / "clamav.md"

    @property
    def detect_it_easy_report(self) -> Path:
        return self.output_dir / "detect-it-easy.md"


def run_kirby(
    basics: BasicsPaths,
    *,
    target: Path | None = None,
    engines: str | None = None,
    analysis: str | None = None,
    rescue: str | None = None,
    clear_cache: bool = False,
    top: int | None = None,
) -> int:
    import kirby

    argv: list[str] = [
        "-t",
        str(target if target is not None else basics.mount),
        "-n",
        basics.namespace,
        "-o",
        str(basics.output_root),
        "-s",
    ]
    if engines:
        argv.extend(["-e", engines])
    if analysis:
        argv.extend(["-a", analysis])
    if rescue:
        argv.extend(["-r", rescue])
    if clear_cache:
        argv.append("--clear-cache")
    if top is not None:
        argv.extend(["-top", str(top)])

    return kirby.main(argv)


def run_kirby_capture(
    basics: BasicsPaths,
    *,
    target: Path | None = None,
    engines: str | None = None,
    analysis: str | None = None,
    rescue: str | None = None,
    clear_cache: bool = False,
    top: int | None = None,
) -> tuple[int, str]:
    import kirby

    argv: list[str] = [
        "-t",
        str(target if target is not None else basics.mount),
        "-n",
        basics.namespace,
        "-o",
        str(basics.output_root),
        "-s",
    ]
    if engines:
        argv.extend(["-e", engines])
    if analysis:
        argv.extend(["-a", analysis])
    if rescue:
        argv.extend(["-r", rescue])
    if clear_cache:
        argv.append("--clear-cache")
    if top is not None:
        argv.extend(["-top", str(top)])

    stderr = io.StringIO()
    previous_stderr = sys.stderr
    sys.stderr = stderr
    try:
        exit_code = kirby.main(argv)
    finally:
        sys.stderr = previous_stderr
    return exit_code, stderr.getvalue()
