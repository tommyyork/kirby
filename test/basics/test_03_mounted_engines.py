"""Mounted-target basics tests for inventory caching and scan engine output."""

from __future__ import annotations

import pytest

from kirby import EXIT_SUCCESS
from test.basics.helpers import run_kirby
from test.conftest import mount_is_active


pytestmark = pytest.mark.basics


def _assert_inventory(basics_paths) -> list[str]:
    assert basics_paths.all_files.is_file(), "file inventory was not written"
    inventory_lines = [
        line.strip()
        for line in basics_paths.all_files.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert inventory_lines, "file inventory is empty"
    assert all(line.startswith(str(basics_paths.mount)) for line in inventory_lines)

    assert basics_paths.all_files_meta.is_file(), "inventory metadata was not written"
    meta = basics_paths.all_files_meta.read_text(encoding="utf-8")
    assert "published_target" in meta
    assert str(basics_paths.mount) in meta

    sha256_path = basics_paths.tmp_dir / "sha256_hashes"
    assert sha256_path.is_file(), "sha256 hash list was not written"
    hash_lines = [
        line.strip()
        for line in sha256_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(hash_lines) == len(inventory_lines)
    return inventory_lines


def test_mount_is_ready_before_engine_runs(basics_paths) -> None:
    assert mount_is_active(basics_paths.mount), (
        f"Expected ISO to be mounted at {basics_paths.mount} before engine tests"
    )
    assert any(basics_paths.mount.iterdir()), (
        f"Mount point {basics_paths.mount} has no content"
    )


def test_yara_writes_report_and_inventory(basics_paths) -> None:
    exit_code = run_kirby(basics_paths, engines="yara", clear_cache=True)
    assert exit_code == EXIT_SUCCESS

    report_path = basics_paths.yara_report
    assert report_path.is_file(), "yara report was not written"
    report = report_path.read_text(encoding="utf-8")
    assert report.startswith("# YARA Scan Report")
    assert f"Target Directory: {basics_paths.mount}" in report
    assert "## Matches" in report

    _assert_inventory(basics_paths)


def test_clamav_writes_report_and_inventory(basics_paths) -> None:
    exit_code = run_kirby(basics_paths, engines="clamav")
    assert exit_code == EXIT_SUCCESS

    report_path = basics_paths.clamav_report
    assert report_path.is_file(), "clamav report was not written"
    report = report_path.read_text(encoding="utf-8")
    assert report.startswith("# ClamAV Scan Report")
    assert f"Target Directory: {basics_paths.mount}" in report
    assert "## Detections" in report

    _assert_inventory(basics_paths)


def test_detect_it_easy_writes_report_and_inventory(basics_paths) -> None:
    exit_code = run_kirby(basics_paths, engines="detect-it-easy")
    assert exit_code == EXIT_SUCCESS

    report_path = basics_paths.detect_it_easy_report
    assert report_path.is_file(), "detect-it-easy report was not written"
    report = report_path.read_text(encoding="utf-8")
    assert report.startswith("# Detect It Easy Scan Report")
    assert f"Target Directory: {basics_paths.mount}" in report
    assert "**Files scanned:**" in report
    assert "## Results" in report or "## Suspicious Results" in report

    _assert_inventory(basics_paths)
