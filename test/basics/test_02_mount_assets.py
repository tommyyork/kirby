"""Mount test assets and verify each mount point has expected content."""

from __future__ import annotations

import platform

import pytest

from test.conftest import (
    MOUNT_ISO_NAME,
    MOUNT_NTFS_NAME,
    attach_iso_readonly,
    attach_ntfs_readonly,
    detach_ntfs_mount,
    find_ntfs_3g,
    mount_is_active,
)


pytestmark = pytest.mark.basics


def test_iso_mount_contains_expected_content(test_paths: dict) -> None:
    if platform.system() != "Darwin":
        pytest.skip("ISO mounting uses macOS hdiutil")

    mount_point = test_paths["mount_iso"]
    iso_path = test_paths["iso"]
    assert mount_point.name == MOUNT_ISO_NAME
    assert iso_path.is_file(), f"Test ISO not found at {iso_path}"

    if not mount_is_active(mount_point):
        attach_iso_readonly(mount_point, iso_path)

    assert mount_is_active(mount_point), (
        f"ISO is not mounted at {mount_point}"
    )

    entries = list(mount_point.iterdir())
    assert entries, f"Mount point {mount_point} is empty"
    names = {entry.name for entry in entries}
    assert {"boot", "minimal"} & names, (
        f"Expected minimal Linux ISO layout under {mount_point}, found: {sorted(names)}"
    )


def test_ntfs_mount_contains_expected_content(test_paths: dict) -> None:
    if platform.system() != "Darwin":
        pytest.skip("NTFS image mounting uses macOS ntfs-3g")

    if find_ntfs_3g() is None:
        pytest.skip("ntfs-3g is required to mount test/assets/ntfs_test.dd")

    mount_point = test_paths["mount_ntfs"]
    image_path = test_paths["ntfs"]
    assert mount_point.name == MOUNT_NTFS_NAME

    if not image_path.is_file():
        pytest.skip(
            f"NTFS test image not found at {image_path}. "
            "Create it with test/assets/create_ntfs_test_image.sh."
        )

    we_mounted = False
    try:
        if not mount_is_active(mount_point):
            attach_ntfs_readonly(mount_point, image_path)
            we_mounted = True

        assert mount_is_active(mount_point), (
            f"NTFS image is not mounted at {mount_point}"
        )

        entries = list(mount_point.iterdir())
        assert entries, f"Mount point {mount_point} is empty"
        names = {entry.name for entry in entries}
        assert {"Program Files", "Windows", "Users"} <= names, (
            f"Expected NTFS test image layout under {mount_point}, found: {sorted(names)}"
        )
    finally:
        if we_mounted and mount_is_active(mount_point):
            detach_ntfs_mount(mount_point)
