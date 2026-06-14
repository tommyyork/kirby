"""Module target-kind metadata and validation for Kirby engines."""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

TargetKind = Literal["device", "folder", "file", "list"]
ModuleKind = Literal["scan", "analysis", "rescue"]

VALID_TARGET_KINDS = frozenset({"device", "folder", "file", "list"})
TARGET_KIND_COLUMNS: tuple[TargetKind, ...] = ("device", "folder", "file", "list")
TARGET_KIND_ALIASES = {"flagged": "list"}
TARGET_LABELS = {
    "device": "device or disk image",
    "folder": "directory or mount point",
    "file": "regular file",
    "list": "CSV file list",
}
SUPPORT_YES = "yes"
SUPPORT_NO = "no"
REPORT_JSON_MARKER = "KIRBY_TARGET_COMPATIBILITY_JSON"

TARGETS_PATTERN = re.compile(
    r"^\s*targets\s*=\s*(?P<value>.+?)\s*(?:#.*)?$",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class EngineTargetRow:
    name: str
    module_kind: ModuleKind
    supported: frozenset[TargetKind]
    passes: bool
    failure_reason: str | None = None

    def supports(self, kind: TargetKind) -> bool:
        return kind in self.supported


@dataclass(frozen=True)
class TargetCompatibilityReport:
    target_kind: TargetKind
    rows: tuple[EngineTargetRow, ...]

    @property
    def target_label(self) -> str:
        return TARGET_LABELS[self.target_kind]

    @property
    def failed_modules(self) -> tuple[str, ...]:
        return tuple(row.name for row in self.rows if not row.passes)

    def has_failures(self) -> bool:
        return bool(self.failed_modules)


def parse_target_kinds(raw: str) -> frozenset[TargetKind]:
    kinds = {
        TARGET_KIND_ALIASES.get(item.strip().lower(), item.strip().lower())
        for item in raw.split(",")
        if item.strip()
    }
    unknown = kinds - VALID_TARGET_KINDS
    if unknown:
        labels = ", ".join(sorted(VALID_TARGET_KINDS))
        unknown_labels = ", ".join(sorted(unknown))
        raise ValueError(
            f"Unknown target kind(s) {unknown_labels!r}; expected one or more of: {labels}"
        )
    if not kinds:
        raise ValueError("targets must list at least one target kind")
    return frozenset(kinds)  # type: ignore[return-value]


def load_module_targets(config_path: Path) -> frozenset[TargetKind]:
    if not config_path.is_file():
        raise FileNotFoundError(f"Module config not found: {config_path}")

    for line in config_path.read_text(encoding="utf-8").splitlines():
        match = TARGETS_PATTERN.match(line)
        if match is None:
            continue
        return parse_target_kinds(match.group("value"))

    raise ValueError(f"Module config is missing required targets setting: {config_path}")


def format_target_kinds(kinds: frozenset[TargetKind]) -> str:
    return ", ".join(sorted(kinds))


def module_requires_list_only(supported: frozenset[TargetKind]) -> bool:
    return supported == frozenset({"list"})


def module_list_unavailable_error(module_name: str, kind: ModuleKind) -> str:
    labels = {
        "scan": "scan module",
        "analysis": "analysis module",
        "rescue": "rescue module",
    }
    return (
        f"{labels[kind]} {module_name!r} requires a populated file list "
        f"(pass -t <paths.csv> or ensure tmp/<name>/flagged.csv has entries)"
    )


def module_target_mismatch_error(
    module_name: str,
    kind: ModuleKind,
    *,
    target_kind: TargetKind,
    supported: frozenset[TargetKind],
) -> str:
    labels = {
        "scan": "scan module",
        "analysis": "analysis module",
        "rescue": "rescue module",
    }
    return (
        f"{labels[kind]} {module_name!r} does not support "
        f"{TARGET_LABELS[target_kind]} targets "
        f"(configured targets: {format_target_kinds(supported)})"
    )


def evaluate_engine_for_target(
    module_name: str,
    module_kind: ModuleKind,
    supported: frozenset[TargetKind],
    *,
    target_kind: TargetKind,
    working_list_available: bool,
) -> tuple[bool, str | None]:
    if module_requires_list_only(supported):
        if not working_list_available:
            return False, module_list_unavailable_error(module_name, module_kind)
        return True, None

    if target_kind not in supported:
        return False, module_target_mismatch_error(
            module_name,
            module_kind,
            target_kind=target_kind,
            supported=supported,
        )
    return True, None


def build_target_compatibility_report(
    modules: Iterable[tuple[str, ModuleKind]],
    *,
    target_kind: TargetKind,
    working_list_available: bool,
    load_supported: Callable[[str, ModuleKind], frozenset[TargetKind]],
) -> TargetCompatibilityReport:
    rows: list[EngineTargetRow] = []
    for module_name, module_kind in modules:
        try:
            supported = load_supported(module_name, module_kind)
        except (FileNotFoundError, ValueError) as exc:
            rows.append(
                EngineTargetRow(
                    name=module_name,
                    module_kind=module_kind,
                    supported=frozenset(),
                    passes=False,
                    failure_reason=str(exc),
                )
            )
            continue

        passes, failure_reason = evaluate_engine_for_target(
            module_name,
            module_kind,
            supported,
            target_kind=target_kind,
            working_list_available=working_list_available,
        )
        rows.append(
            EngineTargetRow(
                name=module_name,
                module_kind=module_kind,
                supported=supported,
                passes=passes,
                failure_reason=failure_reason,
            )
        )
    return TargetCompatibilityReport(target_kind=target_kind, rows=tuple(rows))


def report_to_dict(report: TargetCompatibilityReport) -> dict[str, object]:
    return {
        "target_kind": report.target_kind,
        "target_label": report.target_label,
        "columns": list(TARGET_KIND_COLUMNS),
        "failed_modules": [
            {
                "name": row.name,
                "kind": row.module_kind,
                "reason": row.failure_reason or "",
            }
            for row in report.rows
            if not row.passes
        ],
        "engines": [
            {
                "name": row.name,
                "kind": row.module_kind,
                "supported": {
                    column: row.supports(column) for column in TARGET_KIND_COLUMNS
                },
                "passes": row.passes,
                "failure_reason": row.failure_reason or "",
            }
            for row in report.rows
        ],
    }


def format_ascii_table(headers: list[str], rows: list[list[str]]) -> str:
    """Render a left-aligned ASCII box table for terminal output."""
    if not headers:
        return ""

    column_count = len(headers)
    widths = [len(header) for header in headers]
    for row in rows:
        for index, cell in enumerate(row[:column_count]):
            widths[index] = max(widths[index], len(cell))
        if len(row) < column_count:
            widths.extend(0 for _ in range(column_count - len(row)))

    def horizontal_border() -> str:
        segments = ["-" * (width + 2) for width in widths]
        return "+" + "+".join(segments) + "+"

    def format_row(cells: list[str]) -> str:
        padded = [
            f" {cells[index].ljust(widths[index])} "
            for index, _ in enumerate(widths)
        ]
        for index in range(len(cells), column_count):
            padded[index] = " " * (widths[index] + 2)
        return "|" + "|".join(padded) + "|"

    lines = [horizontal_border(), format_row(headers), horizontal_border()]
    lines.extend(format_row(row) for row in rows)
    lines.append(horizontal_border())
    return "\n".join(lines)


def format_support_table(report: TargetCompatibilityReport) -> str:
    headers = [
        "Engine",
        "Type",
        *[
            f"{column}*" if column == report.target_kind else column
            for column in TARGET_KIND_COLUMNS
        ],
    ]
    rows = [
        [
            row.name,
            row.module_kind,
            *[
                SUPPORT_YES if row.supports(column) else SUPPORT_NO
                for column in TARGET_KIND_COLUMNS
            ],
        ]
        for row in report.rows
    ]
    table = format_ascii_table(headers, rows)
    return f"{table}\n(* = current target kind)"


def format_failed_modules(report: TargetCompatibilityReport) -> str:
    failed_rows = [row for row in report.rows if not row.passes]
    if not failed_rows:
        return "Engines not supported for this target:\n- none"

    lines = ["Engines not supported for this target:"]
    for row in failed_rows:
        lines.append(f"- {row.name} ({row.module_kind})")
    return "\n".join(lines)


def format_target_compatibility_report(report: TargetCompatibilityReport) -> str:
    sections = [
        f"Target compatibility for {report.target_label}:",
        "",
        format_support_table(report),
        "",
        format_failed_modules(report),
        f"{REPORT_JSON_MARKER}:{json.dumps(report_to_dict(report), sort_keys=True)}",
    ]
    return "\n".join(sections)


def parse_target_compatibility_json(text: str) -> dict[str, object]:
    for line in text.splitlines():
        if not line.startswith(f"{REPORT_JSON_MARKER}:"):
            continue
        payload = line.removeprefix(f"{REPORT_JSON_MARKER}:").strip()
        return json.loads(payload)
    raise ValueError(f"Missing {REPORT_JSON_MARKER} payload in Kirby output")


def failed_module_names_from_output(text: str) -> list[str]:
    payload = parse_target_compatibility_json(text)
    failed = payload.get("failed_modules", [])
    if not isinstance(failed, list):
        raise ValueError("failed_modules must be a list")
    names: list[str] = []
    for item in failed:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        if isinstance(name, str):
            names.append(name)
    return names
