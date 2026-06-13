"""Persistent per-volume file inventory for Kirby scan modules."""

from __future__ import annotations

import hashlib
import json
import subprocess
from collections.abc import Iterator
from pathlib import Path

from kirby_log import KirbyLogger

CACHE_DIR = Path(__file__).resolve().parent / "cache" / "volumes"
ALL_FILES_PATH = Path(__file__).resolve().parent / "tmp" / "all_files"
ALL_FILES_META_PATH = Path(__file__).resolve().parent / "tmp" / "all_files.meta"
SHA256_HASHES_PATH = Path(__file__).resolve().parent / "tmp" / "sha256_hashes"


def resolve_mount_point(target: Path) -> Path:
    """Return the mount point for a path inside a mounted filesystem."""
    resolved = target.resolve(strict=False)
    if not resolved.is_dir():
        return resolved

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


def inventory_paths(mount_point: Path, scan_root: str) -> tuple[Path, Path, Path]:
    base = CACHE_DIR / volume_slug(mount_point) / scan_root_slug(scan_root)
    return base / "all_files", base / "sha256_hashes", base / "meta.json"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_hash_cache(cache_path: Path = SHA256_HASHES_PATH) -> dict[str, str]:
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


def lookup_sha256(path: str | Path, cache: dict[str, str] | None = None) -> str:
    normalized = str(Path(path).resolve())
    if cache is None:
        cache = load_hash_cache()
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


def volume_fingerprint(target: Path) -> dict[str, str]:
    """Stable volume identity for cache lookup, independent of st_dev and remounts."""
    mount = mount_entry(target)
    mount_point = Path(mount["mount_point"])
    scan_root = scan_root_relative(target, mount_point)
    diskutil = diskutil_volume_info(mount_point)
    return {
        "mount_point": mount["mount_point"],
        "mount_source": mount["mount_source"],
        "filesystem": mount["filesystem"],
        "scan_root": scan_root,
        "volume_uuid": diskutil.get("Volume UUID", ""),
        "device_identifier": diskutil.get("Device Identifier", ""),
        "total_space": diskutil.get(
            "Total Space",
            diskutil.get("Disk Size", ""),
        ),
    }


def load_file_list_meta(meta_path: Path) -> dict | None:
    if not meta_path.is_file():
        return None
    try:
        return json.loads(meta_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def save_file_list_meta(meta_path: Path, fingerprint: dict, file_count: int) -> None:
    meta_path.parent.mkdir(parents=True, exist_ok=True)
    meta_path.write_text(
        json.dumps(
            {
                "fingerprint": fingerprint,
                "file_count": file_count,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


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
    lines = [f"{path}\t{digest}" for path, digest in entries]
    destination.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return len(entries)


def build_hash_cache_from_file_list(
    files_path: Path,
    hashes_path: Path,
    log: KirbyLogger,
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
        cached_digest = existing.get(path_str, "")
        if cached_digest:
            entries.append((path_str, cached_digest))
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
        entries.append((path_str, digest))
    count = write_hash_cache(entries, hashes_path)
    log.step(
        f"Wrote {count} SHA-256 hash(es) to {hashes_path} "
        f"({reused} reused from cache, {computed} computed)"
    )
    return count


def write_file_list(
    target: Path,
    destination: Path,
    hashes_destination: Path,
    log: KirbyLogger,
) -> int:
    destination.parent.mkdir(parents=True, exist_ok=True)

    log.step(f"Walking target directory: {target}")
    entries: list[tuple[str, str]] = []
    for path in log.progress(iter_target_files(target), desc="Indexing files", unit="file"):
        path_str = str(path)
        digest = ""
        try:
            digest = sha256_file(path)
        except OSError as exc:
            log.step(f"Could not hash {path}: {exc}")
        entries.append((path_str, digest))

    entries.sort(key=lambda item: item[0])
    paths = [path for path, _ in entries]
    destination.write_text("\n".join(paths) + ("\n" if paths else ""), encoding="utf-8")
    write_hash_cache(entries, hashes_destination)
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


def try_import_legacy_inventory(
    target: Path,
    fingerprint: dict[str, str],
    destination: Path,
    meta_path: Path,
    legacy_files_path: Path,
    legacy_meta_path: Path,
    log: KirbyLogger,
) -> int | None:
    if not legacy_files_path.is_file() or not legacy_meta_path.is_file():
        return None

    stored = load_file_list_meta(legacy_meta_path)
    if stored is None:
        return None

    stored_fingerprint = stored.get("fingerprint")
    if not isinstance(stored_fingerprint, dict):
        return None

    if stored_fingerprint == fingerprint:
        file_count = int(stored.get("file_count", 0))
    else:
        migrated = legacy_fingerprint_from_stored(stored_fingerprint)
        if migrated != fingerprint:
            return None
        file_count = int(stored.get("file_count", 0))

    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(legacy_files_path.read_text(encoding="utf-8"), encoding="utf-8")
    save_file_list_meta(meta_path, fingerprint, file_count)
    log.step(f"Migrated legacy inventory to {destination} ({file_count} paths)")
    return file_count


def ensure_hash_cache(
    files_path: Path,
    hashes_path: Path,
    log: KirbyLogger,
) -> None:
    if hashes_path.is_file():
        return
    log.step(f"Building missing SHA-256 cache from {files_path}")
    build_hash_cache_from_file_list(files_path, hashes_path, log)


def ensure_file_list(
    target: Path,
    tmp_files_path: Path,
    tmp_meta_path: Path,
    log: KirbyLogger,
) -> int:
    log.step("Checking whether file inventory is up to date")
    fingerprint = volume_fingerprint(target)
    mount_point = Path(fingerprint["mount_point"])
    scan_root = fingerprint["scan_root"]
    destination, hashes_path, meta_path = inventory_paths(mount_point, scan_root)
    stored = load_file_list_meta(meta_path)

    if log.verbose:
        log.step(f"Volume fingerprint: {json.dumps(fingerprint, sort_keys=True)}")
        log.step(f"Inventory cache: {destination}")

    if (
        destination.is_file()
        and stored is not None
        and stored.get("fingerprint") == fingerprint
    ):
        file_count = int(stored.get("file_count", 0))
        ensure_hash_cache(destination, hashes_path, log)
        publish_inventory(
            destination,
            tmp_files_path,
            hashes_path,
            SHA256_HASHES_PATH,
            meta_path,
            tmp_meta_path,
        )
        log.step(f"Volume unchanged, reusing {destination} ({file_count} paths)")
        if not log.verbose:
            print(f"[kirby] volume unchanged, reusing cached inventory ({file_count} paths)")
        return file_count

    migrated_count = try_import_legacy_inventory(
        target,
        fingerprint,
        destination,
        meta_path,
        tmp_files_path,
        tmp_meta_path,
        log,
    )
    if migrated_count is not None:
        ensure_hash_cache(destination, hashes_path, log)
        publish_inventory(
            destination,
            tmp_files_path,
            hashes_path,
            SHA256_HASHES_PATH,
            meta_path,
            tmp_meta_path,
        )
        if not log.verbose:
            print(f"[kirby] migrated legacy inventory ({migrated_count} paths)")
        return migrated_count

    log.step("Building file inventory")
    file_count = write_file_list(target, destination, hashes_path, log)
    save_file_list_meta(meta_path, fingerprint, file_count)
    publish_inventory(
        destination,
        tmp_files_path,
        hashes_path,
        SHA256_HASHES_PATH,
        meta_path,
        tmp_meta_path,
    )
    log.step(f"Wrote {file_count} paths to {destination}")
    if not log.verbose:
        print(f"[kirby] wrote {file_count} paths to cached inventory")
    return file_count
