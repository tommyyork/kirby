"""Detect and handle serious external-tool failures in Kirby modules."""

from __future__ import annotations

import subprocess
import sys

SERIOUS_STDERR_PREFIXES = ("error:", "fatal:")


def serious_stderr_lines(stderr: str) -> list[str]:
    lines: list[str] = []
    for raw in stderr.splitlines():
        stripped = raw.strip()
        if not stripped:
            continue
        lower = stripped.lower()
        if any(lower.startswith(prefix) for prefix in SERIOUS_STDERR_PREFIXES):
            lines.append(stripped)
    return lines


def tool_failure_message(
    context: str,
    *,
    returncode: int | None = None,
    allowed_returncodes: frozenset[int] | None = None,
    stderr: str = "",
) -> str | None:
    parts: list[str] = []
    if returncode is not None and allowed_returncodes is not None:
        if returncode not in allowed_returncodes:
            parts.append(f"exit code {returncode}")
    elif returncode is not None and returncode != 0:
        parts.append(f"exit code {returncode}")

    parts.extend(serious_stderr_lines(stderr))

    if not parts:
        return None

    detail = "; ".join(dict.fromkeys(parts))
    message = f"{context}: {detail}"
    stderr_text = stderr.strip()
    if stderr_text and not serious_stderr_lines(stderr):
        message = f"{message}\n{stderr_text}"
    return message


def handle_tool_failure(
    message: str,
    *,
    force_errors: bool,
    warnings: list[str] | None = None,
) -> bool:
    if force_errors:
        if warnings is not None:
            warnings.append(message)
        else:
            print(f"Warning: {message}", file=sys.stderr)
        return False
    raise RuntimeError(message)


def check_subprocess(
    result: subprocess.CompletedProcess[str],
    *,
    context: str,
    allowed_returncodes: frozenset[int] = frozenset({0}),
    force_errors: bool = False,
    warnings: list[str] | None = None,
) -> bool:
    message = tool_failure_message(
        context,
        returncode=result.returncode,
        allowed_returncodes=allowed_returncodes,
        stderr=result.stderr or "",
    )
    if message:
        return handle_tool_failure(message, force_errors=force_errors, warnings=warnings)
    return True


def check_command_result(
    returncode: int,
    output: str,
    *,
    context: str,
    allowed_returncodes: frozenset[int] = frozenset({0}),
    force_errors: bool = False,
    warnings: list[str] | None = None,
) -> bool:
    message = tool_failure_message(
        context,
        returncode=returncode,
        allowed_returncodes=allowed_returncodes,
        stderr=output,
    )
    if message:
        return handle_tool_failure(message, force_errors=force_errors, warnings=warnings)
    return True


def is_benign_vt_error(payload: dict) -> bool:
    status = payload.get("_http_status")
    if status == 404:
        return True

    error = payload.get("error")
    if isinstance(error, dict):
        code = str(error.get("code", ""))
        if code in {"NotFoundError"}:
            return True
    return False


def check_vt_payload(
    payload: dict,
    *,
    context: str,
    force_errors: bool = False,
    warnings: list[str] | None = None,
) -> bool:
    error = payload.get("error")
    status = payload.get("_http_status")
    if not error and status is None:
        return True
    if is_benign_vt_error(payload):
        return True

    if isinstance(error, dict):
        code = error.get("code")
        message = error.get("message")
        detail = code or message or "unknown VirusTotal error"
    elif status is not None:
        detail = f"HTTP {status}"
    else:
        detail = "unknown VirusTotal error"

    return handle_tool_failure(
        f"{context}: {detail}",
        force_errors=force_errors,
        warnings=warnings,
    )
