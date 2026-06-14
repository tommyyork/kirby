"""Unit tests for volume inventory fingerprint matching."""

from __future__ import annotations

from kirby_index import fingerprints_match_identity, fingerprint_identity


def test_fingerprints_match_when_volume_uuid_matches_despite_disk_slot_change() -> None:
    stored = {
        "mount_source": "/dev/disk6s3",
        "device_identifier": "disk6s3",
        "volume_uuid": "60EEB5B4-521D-432F-9FE7-D0945E33B7FD",
        "filesystem": "ntfs, local, nodev, nosuid, read-only, noowners, noatime, fskit",
        "total_space": "126.7 GB (126696292352 Bytes) (exactly 247453696 512-Byte-Units)",
    }
    current = {
        "mount_source": "/dev/disk7s3",
        "device_identifier": "disk7s3",
        "volume_uuid": "60EEB5B4-521D-432F-9FE7-D0945E33B7FD",
        "filesystem": "ntfs, local, nodev, nosuid, read-only, noowners, noatime, fskit",
        "total_space": "126.7 GB (126696292352 Bytes) (exactly 247453696 512-Byte-Units)",
    }

    assert fingerprints_match_identity(stored, current)


def test_fingerprints_do_not_match_when_volume_uuid_differs() -> None:
    stored = {
        "volume_uuid": "60EEB5B4-521D-432F-9FE7-D0945E33B7FD",
        "filesystem": "ntfs",
        "total_space": "126.7 GB",
    }
    current = {
        "volume_uuid": "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE",
        "filesystem": "ntfs",
        "total_space": "126.7 GB",
    }

    assert not fingerprints_match_identity(stored, current)


def test_fingerprint_identity_ignores_volatile_mount_fields() -> None:
    identity = fingerprint_identity(
        {
            "mount_source": "/dev/disk6s3",
            "device_identifier": "disk6s3",
            "volume_uuid": "60EEB5B4-521D-432F-9FE7-D0945E33B7FD",
            "filesystem": "ntfs",
            "total_space": "126.7 GB",
        }
    )

    assert "mount_source" not in identity
    assert "device_identifier" not in identity
    assert identity["volume_uuid"] == "60EEB5B4-521D-432F-9FE7-D0945E33B7FD"
