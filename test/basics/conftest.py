"""Fixtures for the basics Kirby integration test suite."""

from __future__ import annotations

from pathlib import Path

import pytest

from test.basics.helpers import BASICS_NAMESPACE, BasicsPaths


@pytest.fixture
def basics_paths(test_paths: dict[str, Path], mounted_target: Path) -> BasicsPaths:
    paths = BasicsPaths(
        namespace=BASICS_NAMESPACE,
        iso=test_paths["iso"],
        mount=mounted_target,
        output_root=test_paths["output"],
        tmp_root=test_paths["tmp"],
    )
    paths.output_dir.mkdir(parents=True, exist_ok=True)
    paths.tmp_dir.mkdir(parents=True, exist_ok=True)
    return paths


@pytest.fixture
def basics_paths_unmounted(test_paths: dict[str, Path]) -> BasicsPaths:
    paths = BasicsPaths(
        namespace=BASICS_NAMESPACE,
        iso=test_paths["iso"],
        mount=test_paths["mount"],
        output_root=test_paths["output"],
        tmp_root=test_paths["tmp"],
    )
    paths.output_dir.mkdir(parents=True, exist_ok=True)
    paths.tmp_dir.mkdir(parents=True, exist_ok=True)
    return paths
