"""Kernel extension discovery and file inventory for Kirby's -kext target."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

from kirby_index import (
    ALL_FILES_META_PATH,
    ALL_FILES_PATH,
    SHA256_HASHES_PATH,
    build_hash_cache_from_file_list,
    load_file_list_meta,
    publish_cached_file,
    save_file_list_meta,
    sha256_file,
    write_hash_cache,
)
from kirby_log import KirbyLogger

KEXT_TARGET = Path("@kext")
KEXT_TARGET_LABEL = "macOS kernel extensions"

CACHE_DIR = Path(__file__).resolve().parent / "cache" / "kext"
KEXT_FILES_PATH = CACHE_DIR / "all_files"
KEXT_HASHES_PATH = CACHE_DIR / "sha256_hashes"
KEXT_META_PATH = CACHE_DIR / "meta.json"

KEXT_SEARCH_ROOTS = (
    Path("/Library/Extensions"),
    Path("/System/Library/Extensions"),
    Path("/Library/Apple/System/Library/Extensions"),
)


def is_kext_target(target: Path | None) -> bool:
    if target is None:
        return False
    return target == KEXT_TARGET or str(target) == KEXT_TARGET_LABEL


def kext_search_roots() -> list[Path]:
    return [path for path in KEXT_SEARCH_ROOTS if path.is_dir()]


def iter_kext_bundles() -> Iterator[Path]:
    seen: set[str] = set()
    for root in kext_search_roots():
        for path in root.rglob("*.kext"):
            if not path.is_dir():
                continue
            try:
                resolved = path.resolve(strict=False)
            except OSError:
                continue
            key = str(resolved)
            if key in seen:
                continue
            seen.add(key)
            yield resolved


def iter_kext_files() -> Iterator[Path]:
    for bundle in iter_kext_bundles():
        for path in bundle.rglob("*"):
            if not path.is_file():
                continue
            try:
                yield path.resolve(strict=False)
            except OSError:
                continue


def kext_fingerprint() -> dict[str, object]:
    bundles: list[dict[str, object]] = []
    for bundle in iter_kext_bundles():
        try:
            mtime_ns = bundle.stat().st_mtime_ns
        except OSError:
            mtime_ns = 0
        bundles.append({"path": str(bundle), "mtime_ns": mtime_ns})
    bundles.sort(key=lambda item: str(item["path"]))
    return {
        "special_target": "kext",
        "bundle_count": len(bundles),
        "bundles": bundles,
    }


def write_kext_file_list(destination: Path, hashes_destination: Path, log: KirbyLogger) -> int:
    destination.parent.mkdir(parents=True, exist_ok=True)

    log.step("Enumerating kernel extension bundles")
    bundles = list(iter_kext_bundles())
    log.step(f"Found {len(bundles)} kext bundle(s)")

    entries: list[tuple[str, str]] = []
    for path in log.progress(iter_kext_files(), desc="Indexing kext files", unit="file"):
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


def publish_kext_inventory(
    source: Path,
    destination: Path,
    hashes_source: Path,
    hashes_destination: Path,
    meta_source: Path,
    meta_destination: Path,
) -> None:
    publish_cached_file(source, destination)
    publish_cached_file(hashes_source, hashes_destination)
    meta_destination.parent.mkdir(parents=True, exist_ok=True)
    meta_destination.write_text(meta_source.read_text(encoding="utf-8"), encoding="utf-8")


def is_kext_path(path_str: str) -> bool:
    normalized = path_str.replace("\\", "/")
    return ".kext/" in normalized or normalized.endswith(".kext")


def ensure_kext_file_list(
    tmp_files_path: Path = ALL_FILES_PATH,
    tmp_meta_path: Path = ALL_FILES_META_PATH,
    log: KirbyLogger | None = None,
) -> int:
    if log is None:
        log = KirbyLogger(True)

    log.step("Checking whether kernel extension inventory is up to date")
    fingerprint = kext_fingerprint()
    stored = load_file_list_meta(KEXT_META_PATH)

    if (
        KEXT_FILES_PATH.is_file()
        and stored is not None
        and stored.get("fingerprint") == fingerprint
    ):
        file_count = int(stored.get("file_count", 0))
        if not KEXT_HASHES_PATH.is_file():
            log.step(f"Building missing SHA-256 cache from {KEXT_FILES_PATH}")
            build_hash_cache_from_file_list(KEXT_FILES_PATH, KEXT_HASHES_PATH, log)
        publish_kext_inventory(
            KEXT_FILES_PATH,
            tmp_files_path,
            KEXT_HASHES_PATH,
            SHA256_HASHES_PATH,
            KEXT_META_PATH,
            tmp_meta_path,
        )
        log.step(f"Kernel extensions unchanged, reusing {KEXT_FILES_PATH} ({file_count} paths)")
        if not log.verbose:
            print(f"[kirby] kext inventory unchanged, reusing cached list ({file_count} paths)")
        return file_count

    log.step("Building kernel extension file inventory")
    file_count = write_kext_file_list(KEXT_FILES_PATH, KEXT_HASHES_PATH, log)
    save_file_list_meta(KEXT_META_PATH, fingerprint, file_count)
    publish_kext_inventory(
        KEXT_FILES_PATH,
        tmp_files_path,
        KEXT_HASHES_PATH,
        SHA256_HASHES_PATH,
        KEXT_META_PATH,
        tmp_meta_path,
    )
    log.step(f"Wrote {file_count} kext file path(s) to {KEXT_FILES_PATH}")
    if not log.verbose:
        print(f"[kirby] wrote {file_count} kext file path(s) to cached inventory")
    return file_count
