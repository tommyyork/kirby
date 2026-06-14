"""Fixtures for Kirby volume cache integration tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from test.cache.helpers import CACHE_NAMESPACE, CachePaths


@pytest.fixture
def cache_paths(test_paths: dict[str, Path], mounted_target: Path) -> CachePaths:
    paths = CachePaths(
        namespace=CACHE_NAMESPACE,
        mount=mounted_target,
        output_root=test_paths["output"],
        tmp_root=test_paths["tmp"],
    )
    paths.tmp_dir.mkdir(parents=True, exist_ok=True)
    paths.output_dir.mkdir(parents=True, exist_ok=True)
    return paths
