"""Target compatibility report structure and Kirby stderr output."""

from __future__ import annotations

import pytest

import kirby
from kirby import EXIT_TARGET_MISMATCH
from kirby_module_targets import (
    SUPPORT_NO,
    SUPPORT_YES,
    TARGET_LABELS,
    TargetKind,
    build_target_compatibility_report,
    failed_module_names_from_output,
    format_support_table,
    format_target_compatibility_report,
    parse_target_compatibility_json,
    report_to_dict,
)
from test.basics.helpers import run_kirby_capture

pytestmark = pytest.mark.basics

ALL_TARGET_KINDS: tuple[TargetKind, ...] = ("device", "folder", "file", "list")


def all_kirby_modules() -> list[tuple[str, kirby.ModuleKind]]:
    """Return every configured Kirby module as (name, kind) pairs."""
    modules: list[tuple[str, kirby.ModuleKind]] = []
    for kind, base in (
        ("scan", kirby.SCAN_MODULES_DIR),
        ("analysis", kirby.ANALYSIS_MODULES_DIR),
        ("rescue", kirby.RESCUE_MODULES_DIR),
    ):
        for module_dir in sorted(base.iterdir()):
            if not module_dir.is_dir():
                continue
            config_path = module_dir / f"{module_dir.name}.conf"
            if config_path.is_file():
                modules.append((module_dir.name, kind))
    return modules


def test_00_print_full_engine_compatibility_reports() -> None:
    """Emit one compatibility table per target kind for every configured engine."""
    modules = all_kirby_modules()

    for target_kind in ALL_TARGET_KINDS:
        working_list_available = target_kind == "list"
        report = build_target_compatibility_report(
            modules,
            target_kind=target_kind,
            working_list_available=working_list_available,
            load_supported=kirby.load_module_supported_targets,
        )
        print()
        print(f"Target type: {target_kind} ({TARGET_LABELS[target_kind]})")
        print()
        print(format_support_table(report))


def test_build_target_compatibility_report_marks_unsupported_engines() -> None:
    supported_by_engine = {
        ("clamav", "scan"): frozenset({"folder", "file", "list"}),
        ("yara", "scan"): frozenset({"folder", "file", "list"}),
        ("sleuthkit-mactime", "analysis"): frozenset({"device"}),
    }

    def load_supported(name: str, kind: str) -> frozenset[str]:
        return supported_by_engine[(name, kind)]

    report = build_target_compatibility_report(
        [
            ("clamav", "scan"),
            ("yara", "scan"),
            ("sleuthkit-mactime", "analysis"),
        ],
        target_kind="device",
        working_list_available=False,
        load_supported=load_supported,
    )

    assert report.failed_modules == ("clamav", "yara")
    clamav = next(row for row in report.rows if row.name == "clamav")
    assert clamav.supports("device") is False
    assert clamav.supports("folder") is True
    sleuthkit = next(row for row in report.rows if row.name == "sleuthkit-mactime")
    assert sleuthkit.passes is True

    payload = report_to_dict(report)
    assert payload["target_kind"] == "device"
    assert [item["name"] for item in payload["failed_modules"]] == ["clamav", "yara"]


def test_format_target_compatibility_report_includes_table_and_json() -> None:
    report = build_target_compatibility_report(
        [("clamav", "scan")],
        target_kind="device",
        working_list_available=False,
        load_supported=lambda _name, _kind: frozenset({"folder", "file", "list"}),
    )
    text = format_target_compatibility_report(report)

    assert "Target compatibility for device or disk image:" in text
    assert "+-" in text
    assert "| Engine " in text
    assert "| device* " in text
    assert f"| clamav " in text
    assert f"| {SUPPORT_NO} " in text
    assert f"| {SUPPORT_YES} " in text
    assert "(* = current target kind)" in text
    assert "Engines not supported for this target:" in text
    assert "- clamav (scan)" in text
    assert "KIRBY_TARGET_COMPATIBILITY_JSON:" in text

    payload = parse_target_compatibility_json(text)
    assert failed_module_names_from_output(text) == ["clamav"]
    assert payload["engines"][0]["supported"]["device"] is False


def test_device_target_lists_each_unsupported_scan_engine(
    basics_paths_unmounted,
) -> None:
    exit_code, stderr = run_kirby_capture(
        basics_paths_unmounted,
        target=basics_paths_unmounted.iso,
        engines="clamav,yara",
    )
    assert exit_code == EXIT_TARGET_MISMATCH
    assert failed_module_names_from_output(stderr) == ["clamav", "yara"]
