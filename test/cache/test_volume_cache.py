"""Volume inventory cache tests for Kirby indexing and reuse."""

from __future__ import annotations

import pytest

from kirby import EXIT_SUCCESS
from test.cache.helpers import (
    assert_cache_reused,
    assert_indexed,
    clear_tmp_namespace,
    clear_volume_cache_for_mount,
    load_tmp_meta,
    run_kirby_capture,
    volume_cache_count,
)


pytestmark = pytest.mark.cache


def test_volume_cache_indexing_and_reuse(cache_paths) -> None:
    """Exercise fresh indexing, limited publish, and full reuse from volume cache."""
    clear_tmp_namespace(cache_paths)
    clear_volume_cache_for_mount(cache_paths.mount)

    cache_files, cache_meta, cache_hashes = cache_paths.volume_cache_files()
    assert not cache_files.is_file(), "volume cache should start empty"

    exit_code, output = run_kirby_capture(cache_paths, clear_cache=True)
    assert exit_code == EXIT_SUCCESS
    assert_indexed(output)

    assert cache_files.is_file(), "volume cache all_files was not created"
    assert cache_meta.is_file(), "volume cache meta.json was not created"
    assert cache_hashes.is_file(), "volume cache sha256_hashes was not created"

    full_cache_count = volume_cache_count(cache_paths)
    assert full_cache_count > 0, "volume cache should contain indexed paths"
    cache_mtime_after_index = cache_files.stat().st_mtime_ns
    assert cache_paths.all_files.is_file()
    assert volume_cache_count(cache_paths) == full_cache_count

    first_meta = load_tmp_meta(cache_paths)
    assert first_meta["cached_count"] == full_cache_count
    assert first_meta["published_count"] == full_cache_count
    assert "publish_limit" not in first_meta

    exit_code, output = run_kirby_capture(cache_paths, top=10)
    assert exit_code == EXIT_SUCCESS
    assert_cache_reused(output)

    assert volume_cache_count(cache_paths) == full_cache_count, (
        "volume cache size changed after -top 10 run"
    )
    assert cache_files.stat().st_mtime_ns == cache_mtime_after_index, (
        "volume cache file was rewritten during -top 10 reuse"
    )

    limited_meta = load_tmp_meta(cache_paths)
    assert limited_meta["cached_count"] == full_cache_count
    assert limited_meta["published_count"] == 10
    assert limited_meta["publish_limit"] == 10

    limited_paths = [
        line.strip()
        for line in cache_paths.all_files.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(limited_paths) == 10

    exit_code, output = run_kirby_capture(cache_paths)
    assert exit_code == EXIT_SUCCESS
    assert_cache_reused(output)

    assert volume_cache_count(cache_paths) == full_cache_count, (
        "volume cache size changed after full reuse run"
    )
    assert cache_files.stat().st_mtime_ns == cache_mtime_after_index, (
        "volume cache file was rewritten during full reuse"
    )

    full_meta = load_tmp_meta(cache_paths)
    assert full_meta["cached_count"] == full_cache_count
    assert full_meta["published_count"] == full_cache_count
    assert "publish_limit" not in full_meta

    full_paths = [
        line.strip()
        for line in cache_paths.all_files.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(full_paths) == full_cache_count
