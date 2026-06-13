"""Shared Markdown report helpers for kirby modules."""

from __future__ import annotations

import configparser
from datetime import datetime, timezone
from pathlib import Path


def scan_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def format_config_lines(config: configparser.ConfigParser, section: str) -> list[str]:
    lines = ["Configuration:"]
    for key, value in config.items(section):
        if key == "default":
            continue
        lines.append(f"- {key}: {value}")
    return lines


def format_target_label(target: Path) -> str:
    if str(target) == "@kext":
        return "macOS kernel extensions (-kext)"
    return str(target)


def format_scan_report_header(
    title: str,
    target: Path,
    config: configparser.ConfigParser,
    section: str,
    *,
    scan_time: str | None = None,
) -> list[str]:
    timestamp = scan_time or scan_timestamp()
    return [
        title,
        f"Target Directory: {format_target_label(target)}",
        f"Scan Time: {timestamp}",
        *format_config_lines(config, section),
        "",
    ]
