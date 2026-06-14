"""Shared pytest fixtures for Kirby integration tests."""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
TEST_ROOT = PROJECT_ROOT / "test"
TEST_ASSETS_DIR = TEST_ROOT / "assets"
TEST_MOUNT_DIR = TEST_ROOT / "mounts"
TEST_OUTPUT_ROOT = TEST_ROOT / "output"
TEST_TMP_ROOT = TEST_ROOT / "tmp"

MOUNT_ISO_NAME = "Kirby ISO"
MOUNT_NTFS_NAME = "Kirby NTFS"
TEST_MOUNT_ISO_DIR = TEST_MOUNT_DIR / MOUNT_ISO_NAME
TEST_MOUNT_NTFS_DIR = TEST_MOUNT_DIR / MOUNT_NTFS_NAME

ISO_NAME = "minimal_linux_live_15-Dec-2019_64-bit_bios.iso"
ISO_PATH = TEST_ASSETS_DIR / ISO_NAME
NTFS_IMAGE_NAME = "ntfs_test.dd"
NTFS_IMAGE_PATH = TEST_ASSETS_DIR / NTFS_IMAGE_NAME

# Route Kirby working files into test/tmp/ for all tests in this tree.
os.environ["KIRBY_TMP_ROOT"] = str(TEST_TMP_ROOT)

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def ensure_test_dirs() -> None:
    for path in (
        TEST_MOUNT_DIR,
        TEST_MOUNT_ISO_DIR,
        TEST_MOUNT_NTFS_DIR,
        TEST_OUTPUT_ROOT,
        TEST_TMP_ROOT,
    ):
        path.mkdir(parents=True, exist_ok=True)


ensure_test_dirs()


def mount_is_active(mount_point: Path) -> bool:
    try:
        result = subprocess.run(
            ["mount"],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return False

    if result.returncode != 0:
        return False

    resolved = mount_point.resolve(strict=False)
    for line in result.stdout.splitlines():
        if " on " not in line:
            continue
        _, _, remainder = line.partition(" on ")
        mounted_at, _, _ = remainder.partition(" (")
        try:
            if Path(mounted_at.strip()).resolve(strict=False) == resolved:
                return True
        except OSError:
            continue
    return False


LEGACY_MOUNT_ISO_DIR = TEST_ROOT / "mount"


def detach_iso_image(iso_path: Path) -> None:
    candidates = [iso_path, LEGACY_MOUNT_ISO_DIR]
    for target in candidates:
        if target == LEGACY_MOUNT_ISO_DIR and not mount_is_active(target):
            continue
        for args in (
            ["hdiutil", "detach", str(target), "-quiet"],
            ["hdiutil", "detach", str(target), "-force", "-quiet"],
        ):
            subprocess.run(
                args,
                capture_output=True,
                text=True,
                check=False,
            )


def attach_iso_readonly(mount_point: Path, iso_path: Path) -> None:
    mount_point.mkdir(parents=True, exist_ok=True)

    def run_attach() -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                "hdiutil",
                "attach",
                "-readonly",
                "-mountpoint",
                str(mount_point),
                str(iso_path),
            ],
            capture_output=True,
            text=True,
            check=False,
        )

    result = run_attach()
    if result.returncode != 0 and "resource busy" in (result.stderr + result.stdout).lower():
        detach_iso_image(iso_path)
        result = run_attach()

    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise RuntimeError(f"Failed to mount {iso_path} at {mount_point}: {detail}")


def find_ntfs_3g() -> str | None:
    for candidate in (
        "ntfs-3g",
        "/opt/homebrew/bin/ntfs-3g",
        "/usr/local/bin/ntfs-3g",
    ):
        if Path(candidate).is_file():
            return candidate
        found = shutil.which(candidate)
        if found:
            return found
    return None


def attach_ntfs_readonly(mount_point: Path, image_path: Path) -> None:
    ntfs_3g = find_ntfs_3g()
    if ntfs_3g is None:
        raise RuntimeError(
            "ntfs-3g not found. Install ntfs-3g-mac:\n"
            "  brew tap gromgit/homebrew-fuse && brew install gromgit/fuse/ntfs-3g-mac"
        )

    mount_point.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        [
            ntfs_3g,
            "-o",
            "local,allow_other,ro",
            str(image_path),
            str(mount_point),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise RuntimeError(
            f"Failed to mount {image_path} at {mount_point}: {detail}"
        )


def detach_mount(mount_point: Path) -> None:
    subprocess.run(
        ["hdiutil", "detach", str(mount_point), "-quiet"],
        capture_output=True,
        text=True,
        check=False,
    )


def detach_ntfs_mount(mount_point: Path) -> None:
    for command in (
        ["umount", str(mount_point)],
        ["diskutil", "unmount", str(mount_point)],
    ):
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode == 0:
            return


@pytest.fixture(scope="session")
def project_root() -> Path:
    return PROJECT_ROOT


@pytest.fixture(scope="session")
def test_paths() -> dict[str, Path]:
    ensure_test_dirs()
    return {
        "root": TEST_ROOT,
        "assets": TEST_ASSETS_DIR,
        "mount": TEST_MOUNT_ISO_DIR,
        "mount_iso": TEST_MOUNT_ISO_DIR,
        "mount_ntfs": TEST_MOUNT_NTFS_DIR,
        "output": TEST_OUTPUT_ROOT,
        "tmp": TEST_TMP_ROOT,
        "iso": ISO_PATH,
        "ntfs": NTFS_IMAGE_PATH,
    }


@pytest.fixture(scope="session")
def mounted_target(test_paths: dict[str, Path]) -> Iterator[Path]:
    """Mount the minimal Linux ISO read-only at test/mounts/Kirby ISO for the session."""
    if platform.system() != "Darwin":
        pytest.skip("ISO mounting uses macOS hdiutil")

    mount_point = test_paths["mount_iso"]
    iso_path = test_paths["iso"]
    ensure_test_dirs()

    if not iso_path.is_file():
        raise FileNotFoundError(
            f"Test ISO not found at {iso_path}. "
            "Download it into test/assets before running tests."
        )

    we_mounted = False
    if not mount_is_active(mount_point):
        attach_iso_readonly(mount_point, iso_path)
        we_mounted = True

    if not mount_is_active(mount_point):
        raise RuntimeError(f"ISO mount did not become active at {mount_point}")

    entries = list(mount_point.iterdir())
    if not entries:
        raise RuntimeError(f"Mount point {mount_point} is empty after attaching ISO")

    yield mount_point.resolve(strict=False)

    if we_mounted and mount_is_active(mount_point):
        detach_mount(mount_point)
