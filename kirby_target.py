"""Shared helpers for resolving Kirby scan/analysis targets."""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path
from typing import Literal


def is_block_device(path: Path) -> bool:
    try:
        return path.is_block_device() or stat.S_ISBLK(path.stat().st_mode)
    except OSError:
        return False


def is_disk_image_or_device(path: Path) -> bool:
    """True for readable raw images, block devices, and other non-directory targets."""
    if path.is_dir():
        return False

    try:
        mode = path.stat().st_mode
    except OSError:
        return False

    if stat.S_ISREG(mode) or stat.S_ISBLK(mode) or stat.S_ISCHR(mode):
        return os.access(path, os.R_OK)

    return os.access(path, os.R_OK)


def is_mount_table_source(path: Path) -> bool:
    """True when the path is the backing source for an active mount entry."""
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

    candidates = {str(path), str(path.resolve(strict=False))}
    for line in result.stdout.splitlines():
        if " on " not in line:
            continue
        source, _, _ = line.partition(" on ")
        source = source.strip()
        if source in candidates:
            return True

    return False


def is_regular_file_target(path: Path) -> bool:
    """True when -t points at a single regular file to scan."""
    try:
        return path.is_file()
    except OSError:
        return False


def is_file_list_target(path: Path | None) -> bool:
    """True when -t points at an explicit CSV path list."""
    if path is None:
        return False
    try:
        return path.is_file() and path.suffix.lower() == ".csv"
    except OSError:
        return False


def is_scan_target(path: Path) -> bool:
    """True for directory, single-file, or -kext-style scan targets."""
    return path.is_dir() or is_regular_file_target(path)


def is_analysis_target(path: Path) -> bool:
    """True for mount points, disk images, block devices, files, lists, and mount sources."""
    return (
        is_file_list_target(path)
        or path.is_dir()
        or is_regular_file_target(path)
        or is_disk_image_or_device(path)
        or is_mount_table_source(path)
    )


def classify_target_kind(
    target: Path | None,
    *,
    kext_only: bool = False,
) -> Literal["device", "folder", "file", "list"]:
    """Classify -t for module target compatibility checks."""
    if target is None:
        return "list"
    if kext_only:
        return "folder"
    if is_file_list_target(target):
        return "list"
    if is_disk_image_or_device(target):
        return "device"
    if is_regular_file_target(target):
        return "file"
    if target.is_dir():
        return "folder"
    if is_mount_table_source(target):
        return "device"
    raise ValueError(f"Unable to classify target kind for {target!r}")


def mount_point_for_source(source: Path) -> Path | None:
    """Return the mount point when source is the backing device or image for a mount."""
    candidates = {str(source), str(source.resolve(strict=False))}
    try:
        result = subprocess.run(
            ["mount"],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return None

    if result.returncode != 0:
        return None

    for line in result.stdout.splitlines():
        if " on " not in line:
            continue
        mount_source, _, remainder = line.partition(" on ")
        if mount_source.strip() not in candidates:
            continue
        mount_point, _, _ = remainder.partition(" (")
        mount_point = mount_point.strip()
        if mount_point:
            return Path(mount_point).resolve(strict=False)
    return None


def resolve_flagged_filter_root(target: Path) -> Path:
    """Resolve -t target to a directory or file root for flagged-path filtering."""
    resolved = target.resolve(strict=False)
    if resolved.is_file():
        return resolved
    if resolved.is_dir():
        return resolved

    mount_point = mount_point_for_source(resolved)
    if mount_point is not None:
        return mount_point

    return resolved
