"""Persistent per-volume file inventory for Kirby scan modules."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from kirby_log import KirbyLogger

CACHE_DIR = Path(__file__).resolve().parent / "cache" / "volumes"


def resolve_mount_point(target: Path) -> Path:
    """Return the mount point for a path inside a mounted filesystem."""
    resolved = target.resolve(strict=False)

    try:
        result = subprocess.run(
            ["mount"],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return resolved

    if result.returncode != 0:
        return resolved

    best_match = ""
    for line in result.stdout.splitlines():
        if " on " not in line:
            continue
        _, _, remainder = line.partition(" on ")
        mount_point, _, _ = remainder.partition(" (")
        mount_point = mount_point.strip()
        if not mount_point:
            continue
        try:
            mount_path = Path(mount_point).resolve(strict=False)
        except OSError:
            continue
        if resolved == mount_path or resolved.is_relative_to(mount_path):
            if len(mount_point) > len(best_match):
                best_match = mount_point

    return Path(best_match).resolve(strict=False) if best_match else resolved


def mount_entry(target: Path) -> dict[str, str]:
    """Return mount metadata for the filesystem containing target."""
    mount_point = resolve_mount_point(target)
    resolved_mount = str(mount_point)

    try:
        result = subprocess.run(
            ["mount"],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return {"mount_point": resolved_mount, "mount_source": "", "filesystem": ""}

    if result.returncode != 0:
        return {"mount_point": resolved_mount, "mount_source": "", "filesystem": ""}

    for line in result.stdout.splitlines():
        if " on " not in line:
            continue
        source, _, remainder = line.partition(" on ")
        mount_path, _, filesystem = remainder.partition(" (")
        mount_path = mount_path.strip()
        try:
            if Path(mount_path).resolve(strict=False) != mount_point:
                continue
        except OSError:
            if mount_path != resolved_mount:
                continue
        return {
            "mount_point": resolved_mount,
            "mount_source": source.strip(),
            "filesystem": filesystem.rstrip(")").strip(),
        }

    return {"mount_point": resolved_mount, "mount_source": "", "filesystem": ""}


def scan_root_relative(target: Path, mount_point: Path) -> str:
    """Relative path from the mount point to the scan root, or '.' for the mount root."""
    resolved_target = target.resolve(strict=False)
    resolved_mount = mount_point.resolve(strict=False)
    if resolved_target == resolved_mount:
        return "."
    return resolved_target.relative_to(resolved_mount).as_posix()


def volume_slug(mount_point: Path) -> str:
    slug = mount_point.as_posix().strip("/").replace("/", "-")
    return slug or "root"


def scan_root_slug(scan_root: str) -> str:
    if scan_root in {".", ""}:
        return "_root"
    return scan_root.replace("/", "-")


def volume_cache_key(identity: dict[str, str]) -> str:
    """Stable cache directory name keyed by volume UUID when available."""
    volume_uuid = identity.get("volume_uuid", "").strip()
    if volume_uuid:
        return volume_uuid
    device = identity.get("device_identifier", "").strip()
    if device:
        return f"device-{device}"
    mount_point = identity.get("mount_point", "").strip()
    return volume_slug(Path(mount_point)) if mount_point else "unknown-volume"


def inventory_paths(identity: dict[str, str]) -> tuple[Path, Path, Path]:
    base = CACHE_DIR / volume_cache_key(identity) / "_root"
    return base / "all_files", base / "sha256_hashes", base / "meta.json"


def legacy_inventory_paths(mount_point: Path, scan_root: str) -> tuple[Path, Path, Path]:
    """Legacy mount-slug cache layout keyed by scan scope (migration source only)."""
    base = CACHE_DIR / volume_slug(mount_point) / scan_root_slug(scan_root)
    return base / "all_files", base / "sha256_hashes", base / "meta.json"


def cache_path_is_relative(path_str: str) -> bool:
    return not Path(path_str).is_absolute()


def shrink_cache_path(abs_path: str | Path, mount_point: Path) -> str:
    resolved = Path(abs_path).resolve(strict=False)
    mount_resolved = mount_point.resolve(strict=False)
    if resolved == mount_resolved:
        return "."
    return resolved.relative_to(mount_resolved).as_posix()


def expand_cache_path(path_str: str, mount_point: Path) -> str:
    if not cache_path_is_relative(path_str):
        return path_str
    mount_resolved = mount_point.resolve(strict=False)
    if path_str in {".", ""}:
        return str(mount_resolved)
    return str(mount_resolved / path_str)


def read_cached_path_list(files_path: Path, mount_point: Path) -> list[str]:
    return [
        expand_cache_path(path_str, mount_point)
        for path_str in read_path_list(files_path)
    ]


def write_cached_path_list(
    files_path: Path,
    absolute_paths: list[str],
    mount_point: Path,
) -> int:
    relative_paths = [shrink_cache_path(path_str, mount_point) for path_str in absolute_paths]
    return write_path_list(files_path, relative_paths)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_hash_cache(cache_path: Path) -> dict[str, str]:
    if not cache_path.is_file():
        return {}

    cache: dict[str, str] = {}
    for line in cache_path.read_text(encoding="utf-8").splitlines():
        if "\t" not in line:
            continue
        path, digest = line.split("\t", 1)
        path = path.strip()
        digest = digest.strip()
        if path:
            cache[path] = digest
    return cache


def lookup_sha256(
    path: str | Path,
    cache: dict[str, str] | None = None,
    *,
    cache_path: Path | None = None,
) -> str:
    normalized = str(Path(path).resolve())
    if cache is None:
        if cache_path is None:
            return ""
        cache = load_hash_cache(cache_path)
    return cache.get(normalized, "") or cache.get(str(path), "")


def diskutil_volume_info(mount_point: Path) -> dict[str, str]:
    try:
        result = subprocess.run(
            ["diskutil", "info", str(mount_point)],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return {}

    if result.returncode != 0:
        return {}

    info: dict[str, str] = {}
    for line in result.stdout.splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        info[key.strip()] = value.strip()
    return info


VOLUME_IDENTITY_KEYS = (
    "volume_uuid",
    "filesystem",
    "total_space",
)


def volume_identity(target: Path) -> dict[str, str]:
    """Stable volume identity for cache lookup, independent of scan scope."""
    mount = mount_entry(target)
    mount_point = Path(mount["mount_point"])
    diskutil = diskutil_volume_info(mount_point)
    return {
        "mount_point": mount["mount_point"],
        "mount_source": mount["mount_source"],
        "filesystem": mount["filesystem"],
        "volume_uuid": diskutil.get("Volume UUID", ""),
        "device_identifier": diskutil.get("Device Identifier", ""),
        "total_space": diskutil.get(
            "Total Space",
            diskutil.get("Disk Size", ""),
        ),
    }


def fingerprint_identity(fingerprint: dict) -> dict[str, str]:
    return {key: str(fingerprint.get(key, "")) for key in VOLUME_IDENTITY_KEYS}


def fingerprints_match_identity(stored: dict, identity: dict[str, str]) -> bool:
    """Match cached volume identity, ignoring volatile disk slot assignment on remount."""
    stored_uuid = str(stored.get("volume_uuid", "")).strip()
    current_uuid = str(identity.get("volume_uuid", "")).strip()
    if stored_uuid and current_uuid:
        return stored_uuid == current_uuid
    return fingerprint_identity(stored) == fingerprint_identity(identity)


def volume_fingerprint(target: Path) -> dict[str, str]:
    """Volume identity plus the scan scope derived from the target path."""
    mount_point = Path(mount_entry(target)["mount_point"])
    identity = volume_identity(target)
    return {
        **identity,
        "scan_root": scan_root_relative(target, mount_point),
    }


def load_file_list_meta(meta_path: Path) -> dict | None:
    if not meta_path.is_file():
        return None
    try:
        return json.loads(meta_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def save_file_list_meta(meta_path: Path, identity: dict[str, str], file_count: int) -> None:
    meta_path.parent.mkdir(parents=True, exist_ok=True)
    meta_path.write_text(
        json.dumps(
            {
                "fingerprint": identity,
                "file_count": file_count,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def save_published_meta(
    meta_path: Path,
    *,
    identity: dict[str, str],
    published_target: Path,
    published_count: int,
    cached_count: int,
    cache_files: Path,
    publish_limit: int | None = None,
    scoped_count: int | None = None,
) -> None:
    meta_path.parent.mkdir(parents=True, exist_ok=True)
    payload: dict[str, object] = {
        "fingerprint": identity,
        "published_target": str(published_target),
        "published_count": published_count,
        "cached_count": cached_count,
        "cached_inventory": str(cache_files),
    }
    if publish_limit is not None:
        payload["publish_limit"] = publish_limit
    if scoped_count is not None:
        payload["scoped_count"] = scoped_count
    meta_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def publish_cached_file(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)

    resolved_source = source.resolve()
    if destination.is_symlink() or destination.is_file():
        destination.unlink()
    elif destination.is_dir():
        raise RuntimeError(f"Expected file path for cached artifact, found directory: {destination}")
    destination.symlink_to(resolved_source)


def publish_inventory(
    source: Path,
    destination: Path,
    hashes_source: Path,
    hashes_destination: Path,
    meta_source: Path,
    meta_destination: Path,
) -> None:
    """Expose the cached inventory and SHA-256 hashes through tmp/."""
    publish_cached_file(source, destination)
    publish_cached_file(hashes_source, hashes_destination)
    meta_destination.parent.mkdir(parents=True, exist_ok=True)
    meta_destination.write_text(meta_source.read_text(encoding="utf-8"), encoding="utf-8")


def path_is_under_target(path: Path, target: Path) -> bool:
    target_resolved = target.resolve(strict=False)
    try:
        resolved = path.resolve(strict=False)
    except OSError:
        resolved = path
    try:
        return resolved == target_resolved or resolved.is_relative_to(target_resolved)
    except ValueError:
        target_str = str(target_resolved)
        path_str = str(resolved)
        return path_str == target_str or path_str.startswith(f"{target_str}/")


def stored_mount_point(path_str: str) -> Path | None:
    path = Path(path_str)
    if not path.is_absolute() or len(path.parts) < 3:
        return None
    return Path(path.parts[0]) / path.parts[1] / path.parts[2]


def remap_path_to_mount(path_str: str, stored_mount: Path, current_mount: Path) -> str:
    relative = Path(path_str).relative_to(stored_mount.resolve(strict=False))
    return str(current_mount.resolve(strict=False) / relative)


def filter_paths_for_target(
    paths: list[str],
    target: Path,
    *,
    mount_point: Path | None = None,
) -> list[str]:
    filtered: list[str] = []
    for path_str in paths:
        if path_is_under_target(Path(path_str), target):
            filtered.append(path_str)

    if filtered or not paths or mount_point is None:
        return filtered

    stored_mount = stored_mount_point(paths[0])
    current_mount = mount_point.resolve(strict=False)
    if stored_mount is None or stored_mount.resolve(strict=False) == current_mount:
        return filtered

    remapped: list[str] = []
    for path_str in paths:
        try:
            candidate = remap_path_to_mount(path_str, stored_mount, current_mount)
        except ValueError:
            continue
        if path_is_under_target(Path(candidate), target):
            remapped.append(candidate)
    return remapped


def read_path_list(files_path: Path) -> list[str]:
    if not files_path.is_file():
        return []
    return [
        line.strip()
        for line in files_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def count_indexed_paths(files_path: Path) -> int:
    if not files_path.is_file():
        return 0
    if files_path.is_symlink():
        return count_indexed_paths(files_path.resolve())
    return len(read_path_list(files_path))


def remove_path_for_write(path: Path) -> None:
    """Remove a file or symlink so a new regular file can be written at path."""
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.is_dir():
        raise RuntimeError(f"Expected file path, found directory: {path}")


def write_path_list(files_path: Path, paths: list[str]) -> int:
    files_path.parent.mkdir(parents=True, exist_ok=True)
    remove_path_for_write(files_path)
    files_path.write_text("\n".join(paths) + ("\n" if paths else ""), encoding="utf-8")
    return len(paths)


def filter_hash_cache_for_target(
    hashes_path: Path,
    allowed_paths: set[str],
    *,
    mount_point: Path | None = None,
) -> list[tuple[str, str]]:
    if not hashes_path.is_file():
        return []

    allowed_relative: set[str] | None = None
    if mount_point is not None:
        allowed_relative = {shrink_cache_path(path, mount_point) for path in allowed_paths}

    entries: list[tuple[str, str]] = []
    for line in hashes_path.read_text(encoding="utf-8").splitlines():
        if "\t" not in line:
            continue
        path, digest = line.split("\t", 1)
        path = path.strip()
        digest = digest.strip()
        if not path:
            continue
        if path in allowed_paths or (allowed_relative is not None and path in allowed_relative):
            if mount_point is not None:
                path = expand_cache_path(path, mount_point)
            entries.append((path, digest))
    return entries


def target_scope_is_mount_root(target: Path, mount_point: Path) -> bool:
    return scan_root_relative(target, mount_point) in {".", ""}


def publish_filtered_inventory(
    source_files: Path,
    destination_files: Path,
    hashes_source: Path,
    destination_hashes: Path,
    meta_source: Path,
    destination_meta: Path,
    target: Path,
    *,
    mount_point: Path,
    identity: dict[str, str],
    max_paths: int | None = None,
) -> int:
    paths = filter_paths_for_target(
        read_cached_path_list(source_files, mount_point),
        target,
        mount_point=mount_point,
    )
    scoped_count = len(paths)
    publish_limit = max_paths
    if max_paths is not None:
        paths = paths[:max_paths]
    allowed_paths = set(paths)
    write_path_list(destination_files, paths)

    hash_entries = filter_hash_cache_for_target(
        hashes_source,
        allowed_paths,
        mount_point=mount_point,
    )
    write_hash_cache(hash_entries, destination_hashes)

    cached_count = count_indexed_paths(source_files)
    save_published_meta(
        destination_meta,
        identity=identity,
        published_target=target,
        published_count=len(paths),
        cached_count=cached_count,
        cache_files=source_files,
        publish_limit=publish_limit,
        scoped_count=scoped_count,
    )
    return len(paths)


def diagnose_inventory_cache(
    files_path: Path,
    meta_path: Path,
    identity: dict[str, str],
) -> str | None:
    """Return a human-readable reason when a cache entry cannot be reused."""
    if not files_path.is_file():
        return "cache file list is missing"

    stored = load_file_list_meta(meta_path)
    if stored is None:
        return "cache metadata is missing or unreadable"

    stored_fingerprint = stored.get("fingerprint")
    if not isinstance(stored_fingerprint, dict):
        return "cache metadata has no fingerprint"

    if not fingerprints_match_identity(stored_fingerprint, identity):
        return "cache fingerprint does not match the current volume identity"

    stored_count = int(stored.get("file_count", 0))
    actual_count = count_indexed_paths(files_path)
    if stored_count != actual_count:
        return (
            f"cache file_count mismatch (meta={stored_count}, "
            f"all_files={actual_count})"
        )

    return None


def invalidate_inventory_cache(
    files_path: Path,
    meta_path: Path,
    log: KirbyLogger,
    reason: str,
) -> None:
    log.step(f"Invalidating volume cache at {files_path.parent}: {reason}")
    hashes_path = files_path.parent / "sha256_hashes"
    for path in (files_path, meta_path, hashes_path):
        if path.is_symlink() or path.is_file():
            path.unlink()
        elif path.is_dir():
            raise RuntimeError(f"Expected inventory file, found directory: {path}")


def log_inventory_diagnostics(
    *,
    tmp_files_path: Path,
    tmp_meta_path: Path,
    cache_files: Path | None,
    cache_meta: Path | None,
    target: Path,
    mount_point: Path,
    log: KirbyLogger,
) -> None:
    tmp_count = count_indexed_paths(tmp_files_path)
    tmp_meta = load_file_list_meta(tmp_meta_path) if tmp_meta_path.is_file() else None
    cached_count = count_indexed_paths(cache_files) if cache_files is not None else 0

    scope_label = "mount root" if target_scope_is_mount_root(target, mount_point) else str(target)
    log.step(
        f"Inventory diagnostics: published tmp/all_files has {tmp_count} path(s) "
        f"for scope `{scope_label}`"
    )

    if cache_files is not None:
        cache_issue = (
            diagnose_inventory_cache(
                cache_files,
                cache_meta,
                fingerprint_identity(volume_identity(target)),
            )
            if cache_meta is not None
            else "cache metadata is missing"
        )
        if cache_issue:
            log.step(
                f"Volume cache at {cache_files} lists {cached_count} path(s) "
                f"but is not reusable ({cache_issue})"
            )
        else:
            meta_count = int((load_file_list_meta(cache_meta) or {}).get("file_count", cached_count))
            log.step(
                f"Volume cache at {cache_files} is valid with {cached_count} path(s) "
                f"(meta file_count={meta_count})"
            )

    if tmp_meta is not None:
        published_count = tmp_meta.get("published_count")
        cached_total = tmp_meta.get("cached_count")
        publish_limit = tmp_meta.get("publish_limit")
        scoped_count = tmp_meta.get("scoped_count")
        if publish_limit is not None:
            log.step(
                f"Previous tmp/all_files.meta was limited to {publish_limit} path(s) (-top)"
            )
        if published_count is not None and cached_total is not None:
            suffix = ""
            if scoped_count is not None and int(published_count) < int(scoped_count):
                suffix = f" (full scope has {scoped_count} path(s))"
            log.step(
                f"Previous tmp/all_files.meta recorded {published_count} published path(s) "
                f"from a volume cache of {cached_total}{suffix}"
            )
        elif "file_count" in tmp_meta:
            log.step(
                f"Previous tmp/all_files.meta recorded file_count={tmp_meta.get('file_count')}"
            )


def resolve_inventory_cache(
    mount_point: Path,
    scan_root: str,
    identity: dict[str, str],
) -> tuple[Path, Path, Path] | None:
    mount_files, mount_hashes, mount_meta = inventory_paths(identity)
    if load_cached_inventory(mount_files, mount_meta, identity, mount_point) is not None:
        return mount_files, mount_hashes, mount_meta

    if scan_root not in {".", ""}:
        legacy_files, legacy_hashes, legacy_meta = legacy_inventory_paths(mount_point, scan_root)
        if load_cached_inventory(legacy_files, legacy_meta, identity, mount_point) is not None:
            return legacy_files, legacy_hashes, legacy_meta

    slug_root_files = CACHE_DIR / volume_slug(mount_point) / "_root" / "all_files"
    slug_root_meta = CACHE_DIR / volume_slug(mount_point) / "_root" / "meta.json"
    if load_cached_inventory(slug_root_files, slug_root_meta, identity, mount_point) is not None:
        return (
            slug_root_files,
            slug_root_files.parent / "sha256_hashes",
            slug_root_meta,
        )

    return None


def tmp_inventory_is_current(
    tmp_files_path: Path,
    tmp_meta_path: Path,
    *,
    target: Path,
    cache_files: Path,
    identity: dict[str, str],
    mount_point: Path | None = None,
    require_full_publish: bool = True,
) -> bool:
    published_count = count_indexed_paths(tmp_files_path)
    if published_count == 0:
        return False

    meta = load_file_list_meta(tmp_meta_path)
    if meta is None:
        return False
    if str(meta.get("published_target", "")) != str(target):
        return False
    if str(meta.get("cached_inventory", "")) != str(cache_files):
        return False
    if int(meta.get("published_count", 0)) != published_count:
        return False
    stored_fingerprint = meta.get("fingerprint")
    if not isinstance(stored_fingerprint, dict):
        return False
    if not fingerprints_match_identity(stored_fingerprint, identity):
        return False

    if not require_full_publish:
        return True

    if meta.get("publish_limit") is not None:
        return False

    scoped_count = meta.get("scoped_count")
    if scoped_count is not None:
        return published_count == int(scoped_count)

    if mount_point is not None and cache_files.is_file():
        expected = len(
            filter_paths_for_target(
                read_cached_path_list(cache_files, mount_point),
                target,
                mount_point=mount_point,
            )
        )
        return published_count == expected

    return True


def reuse_cached_inventory(
    cache_files: Path,
    cache_hashes: Path,
    cache_meta: Path,
    tmp_files_path: Path,
    tmp_hashes_path: Path,
    tmp_meta_path: Path,
    *,
    target: Path,
    mount_point: Path,
    identity: dict[str, str],
    log: KirbyLogger,
    top_n: int | None = None,
) -> int:
    cached_total = load_cached_inventory(cache_files, cache_meta, identity, mount_point) or count_indexed_paths(
        cache_files
    )
    if top_n is None and tmp_inventory_is_current(
        tmp_files_path,
        tmp_meta_path,
        target=target,
        cache_files=cache_files,
        identity=identity,
        mount_point=mount_point,
        require_full_publish=True,
    ):
        log.step(
            f"Reusing published inventory at {tmp_files_path} "
            f"({count_indexed_paths(tmp_files_path)} path(s) for {target})"
        )
        return count_indexed_paths(tmp_files_path)

    ensure_hash_cache(cache_files, cache_hashes, log, mount_point=mount_point)
    scoped_count = publish_inventory_for_target(
        cache_files,
        tmp_files_path,
        cache_hashes,
        tmp_hashes_path,
        cache_meta,
        tmp_meta_path,
        target=target,
        mount_point=mount_point,
        identity=identity,
        max_paths=top_n,
    )
    log.step(
        f"Volume unchanged, reusing {cache_files} "
        f"({scoped_count} scoped path(s) published to tmp/all_files, "
        f"{cached_total} path(s) in volume cache)"
    )
    if scoped_count == 0 and cached_total > 0:
        log.step(
            f"WARNING: volume cache lists {cached_total} path(s) but none match target "
            f"{target}. Rebuild inventory with `-t {target}` while the volume is mounted."
        )
    if not log.verbose:
        print(
            f"[kirby] volume unchanged, reusing cached inventory "
            f"({scoped_count} scoped / {cached_total} cached path(s))"
        )
    return scoped_count


def load_cached_inventory(
    files_path: Path,
    meta_path: Path,
    identity: dict[str, str],
    mount_point: Path,
) -> int | None:
    if diagnose_inventory_cache(files_path, meta_path, identity) is not None:
        return None
    stored = load_file_list_meta(meta_path)
    if stored is None:
        return None
    return count_indexed_paths(files_path)


def publish_inventory_for_target(
    source_files: Path,
    destination_files: Path,
    hashes_source: Path,
    destination_hashes: Path,
    meta_source: Path,
    destination_meta: Path,
    *,
    target: Path,
    mount_point: Path,
    identity: dict[str, str],
    max_paths: int | None = None,
) -> int:
    if target_scope_is_mount_root(target, mount_point) and max_paths is None:
        paths = read_cached_path_list(source_files, mount_point)
        write_path_list(destination_files, paths)
        hash_entries = filter_hash_cache_for_target(
            hashes_source,
            set(paths),
            mount_point=mount_point,
        )
        hash_lookup = {path: digest for path, digest in hash_entries}
        hash_entries = [(path, hash_lookup.get(path, "")) for path in paths]
        write_hash_cache(hash_entries, destination_hashes)
        cached_count = count_indexed_paths(source_files)
        save_published_meta(
            destination_meta,
            identity=identity,
            published_target=target,
            published_count=len(paths),
            cached_count=cached_count,
            cache_files=source_files,
            scoped_count=len(paths),
        )
        return len(paths)

    if target_scope_is_mount_root(target, mount_point):
        paths = read_cached_path_list(source_files, mount_point)
        scoped_count = len(paths)
        paths = paths[:max_paths]
        allowed_paths = set(paths)
        write_path_list(destination_files, paths)
        hash_entries = filter_hash_cache_for_target(
            hashes_source,
            allowed_paths,
            mount_point=mount_point,
        )
        hash_lookup = {path: digest for path, digest in hash_entries}
        hash_entries = [(path, hash_lookup.get(path, "")) for path in paths]
        write_hash_cache(hash_entries, destination_hashes)
        cached_count = count_indexed_paths(source_files)
        save_published_meta(
            destination_meta,
            identity=identity,
            published_target=target,
            published_count=len(paths),
            cached_count=cached_count,
            cache_files=source_files,
            publish_limit=max_paths,
            scoped_count=scoped_count,
        )
        return len(paths)

    return publish_filtered_inventory(
        source_files,
        destination_files,
        hashes_source,
        destination_hashes,
        meta_source,
        destination_meta,
        target,
        mount_point=mount_point,
        identity=identity,
        max_paths=max_paths,
    )


def iter_target_files(target: Path) -> Iterator[Path]:
    for path in target.rglob("*"):
        if not path.is_file():
            continue
        try:
            yield path.resolve()
        except OSError:
            continue


def write_hash_cache(entries: list[tuple[str, str]], destination: Path) -> int:
    destination.parent.mkdir(parents=True, exist_ok=True)
    remove_path_for_write(destination)
    lines = [f"{path}\t{digest}" for path, digest in entries]
    destination.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return len(entries)


def build_hash_cache_from_file_list(
    files_path: Path,
    hashes_path: Path,
    log: KirbyLogger,
    *,
    mount_point: Path | None = None,
) -> int:
    paths = [
        line.strip()
        for line in files_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    existing = load_hash_cache(hashes_path) if hashes_path.is_file() else {}
    entries: list[tuple[str, str]] = []
    reused = 0
    computed = 0
    for path_str in log.progress(paths, desc="Hashing indexed files", unit="file"):
        cache_key = path_str
        if mount_point is not None and cache_path_is_relative(path_str):
            cache_key = path_str
            path_str = expand_cache_path(path_str, mount_point)

        cached_digest = existing.get(cache_key, "") or existing.get(path_str, "")
        if cached_digest:
            stored_path = cache_key if mount_point is not None else path_str
            entries.append((stored_path, cached_digest))
            reused += 1
            continue

        path = Path(path_str)
        digest = ""
        if path.is_file():
            try:
                digest = sha256_file(path)
                computed += 1
            except OSError as exc:
                log.step(f"Could not hash {path}: {exc}")
        stored_path = cache_key if mount_point is not None else path_str
        entries.append((stored_path, digest))
    count = write_hash_cache(entries, hashes_path)
    log.step(
        f"Wrote {count} SHA-256 hash(es) to {hashes_path} "
        f"({reused} reused from cache, {computed} computed)"
    )
    return count


def limit_inventory(
    files_path: Path,
    hashes_path: Path,
    meta_path: Path | None,
    top_n: int,
    log: KirbyLogger,
) -> int:
    """Keep only the first top_n paths in tmp inventory files."""
    paths = read_path_list(files_path)[:top_n]
    write_path_list(files_path, paths)

    hash_cache = load_hash_cache(hashes_path) if hashes_path.is_file() else {}
    write_hash_cache([(path, hash_cache.get(path, "")) for path in paths], hashes_path)

    if meta_path is not None and meta_path.is_file():
        meta = load_file_list_meta(meta_path)
        if meta is not None:
            meta["published_count"] = len(paths)
            meta["publish_limit"] = top_n
            if "file_count" in meta:
                meta["file_count"] = len(paths)
            meta_path.write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")

    log.step(f"Limited inventory to first {len(paths)} path(s) (-top {top_n})")
    return len(paths)


def write_file_list(
    target: Path,
    destination: Path,
    hashes_destination: Path,
    log: KirbyLogger,
    *,
    hash_files: bool = True,
    max_files: int | None = None,
    mount_point: Path | None = None,
) -> int:
    destination.parent.mkdir(parents=True, exist_ok=True)

    if max_files is not None:
        log.step(f"Walking target directory: {target} (stopping after {max_files} file(s))")
    else:
        log.step(f"Walking target directory: {target}")
    entries: list[tuple[str, str]] = []
    for path in log.progress(iter_target_files(target), desc="Indexing files", unit="file"):
        path_str = str(path)
        digest = ""
        if hash_files:
            try:
                digest = sha256_file(path)
            except OSError as exc:
                log.step(f"Could not hash {path}: {exc}")
        entries.append((path_str, digest))
        if max_files is not None and len(entries) >= max_files:
            log.step(f"Stopped indexing at {max_files} path(s) (-top {max_files})")
            break

    if max_files is None:
        entries.sort(key=lambda item: item[0])
    absolute_paths = [path for path, _ in entries]
    if mount_point is not None:
        write_cached_path_list(destination, absolute_paths, mount_point)
    else:
        write_path_list(destination, absolute_paths)
    if hash_files:
        if mount_point is not None:
            hash_entries = [
                (shrink_cache_path(path, mount_point), digest) for path, digest in entries
            ]
        else:
            hash_entries = entries
        write_hash_cache(hash_entries, hashes_destination)
        log.step(f"Wrote {len(entries)} SHA-256 hash(es) to {hashes_destination}")
    return len(entries)


def legacy_fingerprint_from_stored(stored_fingerprint: dict) -> dict[str, str] | None:
    """Map pre-kirby_index metadata to the current fingerprint shape."""
    target_raw = stored_fingerprint.get("target")
    if not target_raw:
        return None

    target = Path(str(target_raw))
    if not target.exists():
        return None

    return volume_fingerprint(target)


def try_migrate_legacy_layout(
    mount_point: Path,
    identity: dict[str, str],
    destination: Path,
    hashes_destination: Path,
    meta_path: Path,
    log: KirbyLogger,
) -> int | None:
    """Promote the largest valid legacy per-scope cache into the UUID mount-root cache."""
    volume_dir = CACHE_DIR / volume_slug(mount_point)
    if not volume_dir.is_dir():
        return None

    best: tuple[Path, Path, Path, int] | None = None
    for child in sorted(volume_dir.iterdir()):
        if not child.is_dir() or child.name == "_root":
            continue
        files_path = child / "all_files"
        meta_path_legacy = child / "meta.json"
        count = load_cached_inventory(files_path, meta_path_legacy, identity, mount_point)
        if count is None:
            continue
        if best is None or count > best[3]:
            best = (files_path, child / "sha256_hashes", meta_path_legacy, count)

    slug_root = volume_dir / "_root"
    if slug_root.is_dir():
        files_path = slug_root / "all_files"
        meta_path_legacy = slug_root / "meta.json"
        count = load_cached_inventory(files_path, meta_path_legacy, identity, mount_point)
        if count is not None and (best is None or count > best[3]):
            best = (files_path, slug_root / "sha256_hashes", meta_path_legacy, count)

    if best is None:
        return None

    legacy_files, legacy_hashes, legacy_meta, file_count = best
    return promote_inventory_cache(
        legacy_files,
        legacy_hashes,
        legacy_meta,
        identity,
        mount_point,
        destination,
        hashes_destination,
        meta_path,
        log,
        source_label=str(legacy_files.parent),
        file_count=file_count,
    )


def promote_inventory_cache(
    source_files: Path,
    source_hashes: Path,
    source_meta: Path,
    identity: dict[str, str],
    mount_point: Path,
    destination: Path,
    hashes_destination: Path,
    meta_path: Path,
    log: KirbyLogger,
    *,
    source_label: str,
    file_count: int | None = None,
) -> int:
    absolute_paths = read_cached_path_list(source_files, mount_point)
    if file_count is None:
        file_count = len(absolute_paths)

    destination.parent.mkdir(parents=True, exist_ok=True)
    write_cached_path_list(destination, absolute_paths, mount_point)

    if source_hashes.is_file():
        hash_entries = filter_hash_cache_for_target(
            source_hashes,
            set(absolute_paths),
            mount_point=mount_point,
        )
        hash_lookup = {shrink_cache_path(path, mount_point): digest for path, digest in hash_entries}
        relative_entries = [
            (shrink_cache_path(path, mount_point), hash_lookup.get(shrink_cache_path(path, mount_point), ""))
            for path in absolute_paths
        ]
        write_hash_cache(relative_entries, hashes_destination)
    save_file_list_meta(meta_path, identity, file_count)
    log.step(
        f"Migrated inventory from {source_label} to {destination.parent} "
        f"({file_count} paths, volume UUID {identity.get('volume_uuid', 'unknown')})"
    )
    return file_count


def try_import_legacy_inventory(
    target: Path,
    identity: dict[str, str],
    mount_point: Path,
    destination: Path,
    hashes_destination: Path,
    meta_path: Path,
    log: KirbyLogger,
) -> int | None:
    if not target_scope_is_mount_root(target, mount_point):
        return None
    return try_migrate_legacy_layout(
        mount_point,
        identity,
        destination,
        hashes_destination,
        meta_path,
        log,
    )


def normalize_inventory_cache_paths(
    files_path: Path,
    hashes_path: Path,
    mount_point: Path,
    log: KirbyLogger,
) -> None:
    raw_paths = read_path_list(files_path)
    if not raw_paths or all(cache_path_is_relative(path_str) for path_str in raw_paths):
        return

    absolute_paths = [
        expand_cache_path(path_str, mount_point) if cache_path_is_relative(path_str) else path_str
        for path_str in raw_paths
    ]
    write_cached_path_list(files_path, absolute_paths, mount_point)

    if hashes_path.is_file():
        hash_entries = []
        for line in hashes_path.read_text(encoding="utf-8").splitlines():
            if "\t" not in line:
                continue
            path, digest = line.split("\t", 1)
            path = path.strip()
            digest = digest.strip()
            if not path:
                continue
            abs_path = expand_cache_path(path, mount_point) if cache_path_is_relative(path) else path
            hash_entries.append((shrink_cache_path(abs_path, mount_point), digest))
        write_hash_cache(hash_entries, hashes_path)

    log.step(f"Normalized inventory cache paths to volume-relative form in {files_path.parent}")


def ensure_hash_cache(
    files_path: Path,
    hashes_path: Path,
    log: KirbyLogger,
    *,
    mount_point: Path | None = None,
) -> None:
    if hashes_path.is_file():
        return
    log.step(f"Building missing SHA-256 cache from {files_path}")
    build_hash_cache_from_file_list(files_path, hashes_path, log, mount_point=mount_point)


def clear_volume_cache(target: Path, log: KirbyLogger) -> bool:
    """Delete persistent inventory cache entries for the target volume."""
    identity = volume_identity(target)
    mount_point = Path(identity.get("mount_point") or mount_entry(target)["mount_point"])
    cleared = False

    cache_key = volume_cache_key(identity)
    cache_dir = CACHE_DIR / cache_key
    if cache_dir.is_dir():
        shutil.rmtree(cache_dir)
        log.step(f"Cleared volume inventory cache at {cache_dir}")
        cleared = True

    legacy_dir = CACHE_DIR / volume_slug(mount_point)
    if legacy_dir.is_dir() and legacy_dir != cache_dir:
        shutil.rmtree(legacy_dir)
        log.step(f"Cleared legacy volume inventory cache at {legacy_dir}")
        cleared = True

    if not cleared:
        log.step(
            f"No volume inventory cache found for volume UUID "
            f"{identity.get('volume_uuid') or cache_key}"
        )
    elif not log.verbose:
        print(f"[kirby] cleared volume inventory cache for {cache_key}")
    return cleared


def single_file_fingerprint(path: Path) -> dict[str, str]:
    stat = path.stat()
    return {
        "target_kind": "file",
        "path": str(path.resolve(strict=False)),
        "size": str(stat.st_size),
        "mtime_ns": str(stat.st_mtime_ns),
    }


def ensure_single_file_list(
    target: Path,
    tmp_files_path: Path,
    tmp_meta_path: Path,
    tmp_hashes_path: Path,
    log: KirbyLogger,
) -> int:
    resolved = target.resolve(strict=False)
    if not resolved.is_file():
        raise FileNotFoundError(f"File target not found or not a regular file: {target}")

    path_str = str(resolved)
    fingerprint = single_file_fingerprint(resolved)
    stored = load_file_list_meta(tmp_meta_path)

    mount_point = resolve_mount_point(resolved)
    identity = volume_identity(resolved)
    cache_files, cache_hashes, cache_meta = inventory_paths(identity)
    log_inventory_diagnostics(
        tmp_files_path=tmp_files_path,
        tmp_meta_path=tmp_meta_path,
        cache_files=cache_files if cache_files.is_file() else None,
        cache_meta=cache_meta if cache_meta.is_file() else None,
        target=resolved,
        mount_point=mount_point,
        log=log,
    )

    if (
        tmp_files_path.is_file()
        and stored is not None
        and stored.get("fingerprint") == fingerprint
    ):
        log.step(f"Single-file inventory unchanged for {resolved}")
        if not log.verbose:
            print(f"[kirby] reusing single-file inventory for {resolved.name}")
        return 1

    if load_cached_inventory(cache_files, cache_meta, identity, mount_point) is not None:
        cached_paths = read_cached_path_list(cache_files, mount_point)
        if path_str in cached_paths:
            hash_entries = filter_hash_cache_for_target(
                cache_hashes,
                {path_str},
                mount_point=mount_point,
            )
            digest = hash_entries[0][1] if hash_entries else ""
            if not digest:
                try:
                    digest = sha256_file(resolved)
                except OSError as exc:
                    log.step(f"Could not hash {resolved}: {exc}")
            write_path_list(tmp_files_path, [path_str])
            write_hash_cache([(path_str, digest)], tmp_hashes_path)
            save_file_list_meta(tmp_meta_path, fingerprint, 1)
            log.step(
                f"Published single file from volume cache "
                f"({count_indexed_paths(cache_files)} path(s) in cache)"
            )
            if not log.verbose:
                print(f"[kirby] published single file from volume cache")
            return 1

    log.step(f"Indexing single file target: {resolved}")
    digest = ""
    try:
        digest = sha256_file(resolved)
    except OSError as exc:
        log.step(f"Could not hash {resolved}: {exc}")

    write_path_list(tmp_files_path, [path_str])
    write_hash_cache([(path_str, digest)], tmp_hashes_path)
    save_file_list_meta(tmp_meta_path, fingerprint, 1)
    log.step(f"Published 1 path to {tmp_files_path}")
    if not log.verbose:
        print(f"[kirby] indexed single file target {resolved.name}")
    return 1


def ensure_file_list(
    target: Path,
    tmp_files_path: Path,
    tmp_meta_path: Path,
    tmp_hashes_path: Path,
    log: KirbyLogger,
    *,
    hash_files: bool = True,
    top_n: int | None = None,
) -> int:
    log.step("Checking whether file inventory is up to date")
    fingerprint = volume_fingerprint(target)
    identity = fingerprint_identity(fingerprint)
    mount_point = Path(fingerprint["mount_point"])
    scan_root = fingerprint["scan_root"]
    destination, hashes_path, meta_path = inventory_paths(identity)

    if log.verbose:
        log.step(f"Volume fingerprint: {json.dumps(fingerprint, sort_keys=True)}")
        log.step(
            f"Inventory cache: {destination} "
            f"(volume UUID {identity.get('volume_uuid') or volume_cache_key(identity)})"
        )
        if not target_scope_is_mount_root(target, mount_point):
            log.step(
                f"Scan scope `{scan_root}` will filter cached mount inventory for {target}"
            )

    log_inventory_diagnostics(
        tmp_files_path=tmp_files_path,
        tmp_meta_path=tmp_meta_path,
        cache_files=destination if destination.is_file() else None,
        cache_meta=meta_path if meta_path.is_file() else None,
        target=target,
        mount_point=mount_point,
        log=log,
    )

    if destination.is_file():
        cache_issue = diagnose_inventory_cache(destination, meta_path, identity)
        if cache_issue:
            invalidate_inventory_cache(destination, meta_path, log, cache_issue)
        else:
            normalize_inventory_cache_paths(destination, hashes_path, mount_point, log)

    cached = resolve_inventory_cache(mount_point, scan_root, identity)
    if cached is not None:
        cache_files, cache_hashes, cache_meta = cached
        if cache_files != destination and not destination.is_file():
            promote_inventory_cache(
                cache_files,
                cache_hashes,
                cache_meta,
                identity,
                mount_point,
                destination,
                hashes_path,
                meta_path,
                log,
                source_label=str(cache_files.parent),
            )
            cache_files, cache_hashes, cache_meta = destination, hashes_path, meta_path
        return reuse_cached_inventory(
            cache_files,
            cache_hashes,
            cache_meta,
            tmp_files_path,
            tmp_hashes_path,
            tmp_meta_path,
            target=target,
            mount_point=mount_point,
            identity=identity,
            log=log,
            top_n=top_n,
        )

    migrated_count = try_import_legacy_inventory(
        target,
        identity,
        mount_point,
        destination,
        hashes_path,
        meta_path,
        log,
    )
    if migrated_count is not None:
        ensure_hash_cache(destination, hashes_path, log, mount_point=mount_point)
        return reuse_cached_inventory(
            destination,
            hashes_path,
            meta_path,
            tmp_files_path,
            tmp_hashes_path,
            tmp_meta_path,
            target=target,
            mount_point=mount_point,
            identity=identity,
            log=log,
            top_n=top_n,
        )

    if top_n is not None:
        walk_root = mount_point if target_scope_is_mount_root(target, mount_point) else target
        log.step(f"Building limited inventory for {walk_root} (-top {top_n})")
        count = write_file_list(
            walk_root,
            tmp_files_path,
            tmp_hashes_path,
            log,
            hash_files=hash_files,
            max_files=top_n,
        )
        save_published_meta(
            tmp_meta_path,
            identity=identity,
            published_target=target,
            published_count=count,
            cached_count=0,
            cache_files=tmp_files_path,
            publish_limit=top_n,
            scoped_count=count,
        )
        if not log.verbose:
            print(f"[kirby] indexed {count} path(s) (-top {top_n})")
        return count

    if target_scope_is_mount_root(target, mount_point):
        log.step(f"Building file inventory for mount point {mount_point}")
        source_files, source_hashes, source_meta = destination, hashes_path, meta_path
        file_count = write_file_list(
            mount_point,
            source_files,
            source_hashes,
            log,
            hash_files=hash_files,
            mount_point=mount_point,
        )
        save_file_list_meta(source_meta, identity, file_count)
    else:
        source_files, source_hashes, source_meta = destination, hashes_path, meta_path
        log.step(
            f"Building scoped file inventory for {target} "
            f"(mount cache missing; indexing scan scope only)"
        )
        file_count = write_file_list(
            target,
            source_files,
            source_hashes,
            log,
            hash_files=hash_files,
            mount_point=mount_point,
        )
        save_file_list_meta(source_meta, identity, file_count)

    scoped_count = publish_inventory_for_target(
        source_files,
        tmp_files_path,
        source_hashes,
        tmp_hashes_path,
        source_meta,
        tmp_meta_path,
        target=target,
        mount_point=mount_point,
        identity=identity,
    )
    log.step(
        f"Wrote {file_count} path(s) to {source_files} "
        f"({scoped_count} path(s) published for {target})"
    )
    if not log.verbose:
        print(
            f"[kirby] indexed {file_count} path(s); "
            f"published {scoped_count} scoped path(s) for target"
        )
    return scoped_count


@dataclass(frozen=True)
class CacheInventorySource:
    files_path: Path
    mount_point: Path | None
    label: str


def compile_find_pattern(pattern: str) -> re.Pattern[str]:
    """Compile a regex, treating unescaped * and ? as glob wildcards."""
    if any(ch in pattern for ch in "*?") and not any(
        ch in pattern for ch in "[]()+^$|{}\\"
    ):
        glob_pattern = re.escape(pattern).replace(r"\*", ".*").replace(r"\?", ".")
        return re.compile(glob_pattern, re.IGNORECASE)
    return re.compile(pattern, re.IGNORECASE)


def _add_cache_source(
    sources: dict[str, CacheInventorySource],
    files_path: Path,
    mount_point: Path | None,
    label: str,
) -> None:
    key = str(files_path)
    if key not in sources:
        sources[key] = CacheInventorySource(files_path, mount_point, label)


def cache_inventories_for_target(target: Path) -> list[CacheInventorySource]:
    """Return persistent cache inventories associated with a mounted target."""
    identity = volume_identity(target)
    fingerprint = fingerprint_identity(identity)
    mount_point = Path(identity["mount_point"])
    sources: dict[str, CacheInventorySource] = {}

    uuid_files, _, _ = inventory_paths(fingerprint)
    _add_cache_source(
        sources,
        uuid_files,
        mount_point,
        f"volume cache ({volume_cache_key(fingerprint)})",
    )

    slug_root = CACHE_DIR / volume_slug(mount_point) / "_root" / "all_files"
    _add_cache_source(
        sources,
        slug_root,
        mount_point,
        f"legacy cache ({volume_slug(mount_point)})",
    )

    target_uuid = identity.get("volume_uuid", "")
    target_device = identity.get("device_identifier", "")
    if CACHE_DIR.is_dir():
        for child in sorted(CACHE_DIR.iterdir()):
            if not child.is_dir():
                continue
            files_path = child / "_root" / "all_files"
            meta = load_file_list_meta(child / "_root" / "meta.json")
            if meta is None:
                continue
            stored = meta.get("fingerprint") or {}
            if target_uuid and stored.get("volume_uuid") == target_uuid:
                _add_cache_source(sources, files_path, mount_point, f"volume cache ({child.name})")
            elif target_device and stored.get("device_identifier") == target_device:
                _add_cache_source(sources, files_path, mount_point, f"device cache ({child.name})")

    return list(sources.values())


def all_volume_cache_inventories() -> list[CacheInventorySource]:
    """Return persistent volume cache inventories, excluding local system mounts."""
    sources: dict[str, CacheInventorySource] = {}
    if not CACHE_DIR.is_dir():
        return []

    for child in sorted(CACHE_DIR.iterdir()):
        if not child.is_dir():
            continue
        if child.name in {"root"} or child.name.startswith("var-folders-"):
            continue
        files_path = child / "_root" / "all_files"
        meta = load_file_list_meta(child / "_root" / "meta.json")
        mount_point: Path | None = None
        if meta is not None:
            mount_raw = (meta.get("fingerprint") or {}).get("mount_point", "")
            if mount_raw:
                mount_point = Path(str(mount_raw))
        _add_cache_source(sources, files_path, mount_point, f"cache ({child.name})")

    return list(sources.values())


def resolve_find_sources(
    *,
    target: Path | None,
    tmp_files_path: Path | None,
    search_all_caches: bool,
) -> list[CacheInventorySource]:
    sources: dict[str, CacheInventorySource] = {}

    if tmp_files_path is not None:
        _add_cache_source(
            sources,
            tmp_files_path,
            None,
            f"namespace inventory ({tmp_files_path.parent.name})",
        )

    if target is not None:
        for source in cache_inventories_for_target(target):
            _add_cache_source(sources, source.files_path, source.mount_point, source.label)
    elif search_all_caches:
        for source in all_volume_cache_inventories():
            _add_cache_source(sources, source.files_path, source.mount_point, source.label)

    return list(sources.values())


def display_path_for_cache_line(path_str: str, mount_point: Path | None) -> str:
    if mount_point is not None and cache_path_is_relative(path_str):
        return expand_cache_path(path_str, mount_point)
    return path_str


def find_cached_paths(
    pattern: str,
    *,
    target: Path | None = None,
    tmp_files_path: Path | None = None,
    search_all_caches: bool = False,
    log: KirbyLogger | None = None,
) -> list[str]:
    """Search cached inventories for paths matching pattern; return sorted unique paths."""
    regex = compile_find_pattern(pattern)
    sources = resolve_find_sources(
        target=target,
        tmp_files_path=tmp_files_path,
        search_all_caches=search_all_caches,
    )
    if not sources:
        if log is not None:
            log.step("No cache inventories found to search")
        return []

    if log is not None:
        labels = ", ".join(source.label for source in sources if source.files_path.is_file())
        if labels:
            log.step(f"Searching cached inventories: {labels}")
        else:
            log.step("No cache inventory files exist yet for the selected scope")

    matches: list[str] = []
    seen: set[str] = set()
    for source in sources:
        if not source.files_path.is_file():
            continue
        for path_str in read_path_list(source.files_path):
            display = display_path_for_cache_line(path_str, source.mount_point)
            if regex.search(display) or regex.search(path_str):
                if display not in seen:
                    seen.add(display)
                    matches.append(display)

    return sorted(matches)
