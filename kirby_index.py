"""Persistent per-volume file inventory for Kirby scan modules."""

from __future__ import annotations

import hashlib
import json
import subprocess
from collections.abc import Iterator
from pathlib import Path

from kirby_log import KirbyLogger

CACHE_DIR = Path(__file__).resolve().parent / "cache" / "volumes"


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


def inventory_paths(mount_point: Path) -> tuple[Path, Path, Path]:
    base = CACHE_DIR / volume_slug(mount_point) / "_root"
    return base / "all_files", base / "sha256_hashes", base / "meta.json"


def legacy_inventory_paths(mount_point: Path, scan_root: str) -> tuple[Path, Path, Path]:
    """Pre-mount-root cache layout keyed by scan scope."""
    base = CACHE_DIR / volume_slug(mount_point) / scan_root_slug(scan_root)
    return base / "all_files", base / "sha256_hashes", base / "meta.json"


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
    "mount_point",
    "mount_source",
    "filesystem",
    "volume_uuid",
    "device_identifier",
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
    return fingerprint_identity(stored) == identity


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
) -> None:
    meta_path.parent.mkdir(parents=True, exist_ok=True)
    meta_path.write_text(
        json.dumps(
            {
                "fingerprint": identity,
                "published_target": str(published_target),
                "published_count": published_count,
                "cached_count": cached_count,
                "cached_inventory": str(cache_files),
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


def filter_paths_for_target(paths: list[str], target: Path) -> list[str]:
    filtered: list[str] = []
    for path_str in paths:
        if path_is_under_target(Path(path_str), target):
            filtered.append(path_str)
    return filtered


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


def write_path_list(files_path: Path, paths: list[str]) -> int:
    files_path.parent.mkdir(parents=True, exist_ok=True)
    files_path.write_text("\n".join(paths) + ("\n" if paths else ""), encoding="utf-8")
    return len(paths)


def filter_hash_cache_for_target(hashes_path: Path, allowed_paths: set[str]) -> list[tuple[str, str]]:
    if not hashes_path.is_file():
        return []

    entries: list[tuple[str, str]] = []
    for line in hashes_path.read_text(encoding="utf-8").splitlines():
        if "\t" not in line:
            continue
        path, digest = line.split("\t", 1)
        path = path.strip()
        digest = digest.strip()
        if path and path in allowed_paths:
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
    identity: dict[str, str],
) -> int:
    paths = filter_paths_for_target(read_path_list(source_files), target)
    allowed_paths = set(paths)
    write_path_list(destination_files, paths)

    hash_entries = filter_hash_cache_for_target(hashes_source, allowed_paths)
    write_hash_cache(hash_entries, destination_hashes)

    cached_count = count_indexed_paths(source_files)
    save_published_meta(
        destination_meta,
        identity=identity,
        published_target=target,
        published_count=len(paths),
        cached_count=cached_count,
        cache_files=source_files,
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
            diagnose_inventory_cache(cache_files, cache_meta, volume_identity(target))
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
        if published_count is not None and cached_total is not None:
            log.step(
                f"Previous tmp/all_files.meta recorded {published_count} published path(s) "
                f"from a volume cache of {cached_total}"
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
    mount_files, mount_hashes, mount_meta = inventory_paths(mount_point)
    if load_cached_inventory(mount_files, mount_meta, identity) is not None:
        return mount_files, mount_hashes, mount_meta

    if scan_root not in {".", ""}:
        legacy_files, legacy_hashes, legacy_meta = legacy_inventory_paths(mount_point, scan_root)
        if load_cached_inventory(legacy_files, legacy_meta, identity) is not None:
            return legacy_files, legacy_hashes, legacy_meta

    return None


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
) -> int:
    cached_total = load_cached_inventory(cache_files, cache_meta, identity) or count_indexed_paths(
        cache_files
    )
    ensure_hash_cache(cache_files, cache_hashes, log)
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
    )
    log.step(
        f"Volume unchanged, reusing {cache_files} "
        f"({scoped_count} scoped path(s) published to tmp/all_files, "
        f"{cached_total} path(s) in volume cache)"
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
) -> int:
    if target_scope_is_mount_root(target, mount_point):
        publish_inventory(
            source_files,
            destination_files,
            hashes_source,
            destination_hashes,
            meta_source,
            destination_meta,
        )
        return count_indexed_paths(source_files)

    return publish_filtered_inventory(
        source_files,
        destination_files,
        hashes_source,
        destination_hashes,
        meta_source,
        destination_meta,
        target,
        identity=identity,
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


def try_migrate_legacy_layout(
    mount_point: Path,
    identity: dict[str, str],
    destination: Path,
    hashes_destination: Path,
    meta_path: Path,
    log: KirbyLogger,
) -> int | None:
    """Promote the largest valid legacy per-scope cache into the mount-root cache."""
    volume_dir = CACHE_DIR / volume_slug(mount_point)
    if not volume_dir.is_dir():
        return None

    best: tuple[Path, Path, Path, int] | None = None
    for child in sorted(volume_dir.iterdir()):
        if not child.is_dir() or child.name == "_root":
            continue
        files_path = child / "all_files"
        meta_path_legacy = child / "meta.json"
        count = load_cached_inventory(files_path, meta_path_legacy, identity)
        if count is None:
            continue
        if best is None or count > best[3]:
            best = (files_path, child / "sha256_hashes", meta_path_legacy, count)

    if best is None:
        return None

    legacy_files, legacy_hashes, legacy_meta, file_count = best
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(legacy_files.read_text(encoding="utf-8"), encoding="utf-8")
    if legacy_hashes.is_file():
        hashes_destination.parent.mkdir(parents=True, exist_ok=True)
        hashes_destination.write_text(legacy_hashes.read_text(encoding="utf-8"), encoding="utf-8")
    save_file_list_meta(meta_path, identity, file_count)
    log.step(
        f"Migrated legacy inventory from {legacy_files.parent} to {destination} "
        f"({file_count} paths)"
    )
    return file_count


def try_import_legacy_inventory(
    target: Path,
    identity: dict[str, str],
    destination: Path,
    hashes_destination: Path,
    meta_path: Path,
    log: KirbyLogger,
) -> int | None:
    mount_point = Path(identity["mount_point"])
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


def ensure_hash_cache(
    files_path: Path,
    hashes_path: Path,
    log: KirbyLogger,
) -> None:
    if hashes_path.is_file():
        return
    log.step(f"Building missing SHA-256 cache from {files_path}")
    build_hash_cache_from_file_list(files_path, hashes_path, log)


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
    cache_files, cache_hashes, cache_meta = inventory_paths(mount_point)
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

    if load_cached_inventory(cache_files, cache_meta, identity) is not None:
        cached_paths = read_path_list(cache_files)
        if path_str in cached_paths:
            hash_entries = filter_hash_cache_for_target(cache_hashes, {path_str})
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
) -> int:
    log.step("Checking whether file inventory is up to date")
    fingerprint = volume_fingerprint(target)
    identity = fingerprint_identity(fingerprint)
    mount_point = Path(fingerprint["mount_point"])
    scan_root = fingerprint["scan_root"]
    destination, hashes_path, meta_path = inventory_paths(mount_point)

    if log.verbose:
        log.step(f"Volume fingerprint: {json.dumps(fingerprint, sort_keys=True)}")
        log.step(f"Inventory cache: {destination}")
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

    cached = resolve_inventory_cache(mount_point, scan_root, identity)
    if cached is not None:
        cache_files, cache_hashes, cache_meta = cached
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
        )

    migrated_count = try_import_legacy_inventory(
        target,
        identity,
        destination,
        hashes_path,
        meta_path,
        log,
    )
    if migrated_count is not None:
        ensure_hash_cache(destination, hashes_path, log)
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
        )

    log.step(f"Building file inventory for mount point {mount_point}")
    file_count = write_file_list(mount_point, destination, hashes_path, log)
    save_file_list_meta(meta_path, identity, file_count)
    scoped_count = publish_inventory_for_target(
        destination,
        tmp_files_path,
        hashes_path,
        tmp_hashes_path,
        meta_path,
        tmp_meta_path,
        target=target,
        mount_point=mount_point,
        identity=identity,
    )
    log.step(
        f"Wrote {file_count} path(s) to {destination} "
        f"({scoped_count} path(s) published for {target})"
    )
    if not log.verbose:
        print(
            f"[kirby] indexed {file_count} path(s); "
            f"published {scoped_count} scoped path(s) for target"
        )
    return scoped_count
