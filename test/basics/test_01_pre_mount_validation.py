"""Pre-mount basics tests for Kirby target validation and engine failures."""

from __future__ import annotations

import pytest

from kirby import EXIT_MODULE_FAILURE, EXIT_TARGET_MISMATCH
from kirby_module_targets import (
    SUPPORT_NO,
    SUPPORT_YES,
    failed_module_names_from_output,
    parse_target_compatibility_json,
)
from test.basics.helpers import run_kirby, run_kirby_capture


pytestmark = pytest.mark.basics


def test_clamav_rejects_iso_device_target(basics_paths_unmounted) -> None:
    """ClamAV supports folder/file targets only; a disk image should be rejected."""
    exit_code, stderr = run_kirby_capture(
        basics_paths_unmounted,
        target=basics_paths_unmounted.iso,
        engines="clamav",
    )
    assert exit_code == EXIT_TARGET_MISMATCH
    assert failed_module_names_from_output(stderr) == ["clamav"]

    report = parse_target_compatibility_json(stderr)
    assert report["target_kind"] == "device"
    clamav = next(engine for engine in report["engines"] if engine["name"] == "clamav")
    assert clamav["supported"]["device"] is False
    assert clamav["supported"]["folder"] is True
    assert clamav["passes"] is False
    assert SUPPORT_YES in stderr
    assert SUPPORT_NO in stderr


def test_sleuthkit_ntfs_fails_on_non_ntfs_iso(basics_paths_unmounted) -> None:
    """sleuthkit-ntfs accepts device targets but should fail when the image is not NTFS."""
    exit_code = run_kirby(
        basics_paths_unmounted,
        target=basics_paths_unmounted.iso,
        engines="sleuthkit-ntfs",
    )
    assert exit_code == EXIT_MODULE_FAILURE
    assert not (basics_paths_unmounted.output_dir / "sleuthkit-ntfs.md").is_file()
