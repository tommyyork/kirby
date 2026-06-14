"""Shared Sleuth Kit device resolution and command helpers for Kirby modules."""

from __future__ import annotations

import configparser
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from kirby_log import KirbyLogger
from kirby_target import is_block_device, is_disk_image_or_device

ROOT = Path(__file__).resolve().parent
SLEUTHKIT_CONF_PATH = ROOT / "modules/analysis/sleuthkit-mactime/sleuthkit.conf"
SLEUTHKIT_SECTION = "sleuthkit"
NONE_VALUES = frozenset({"", "none", "null"})
DISLOCKER_FILE_NAME = "dislocker-file"


@dataclass(frozen=True)
class ResolvedTarget:
    device: Path
    bitlocker: bool
    password: str | None
    source: str
    image_offset: int | None = None


def load_sleuthkit_settings(log: KirbyLogger) -> configparser.ConfigParser:
    if SLEUTHKIT_CONF_PATH.is_file():
        log.step(f"Loading Sleuth Kit settings from {SLEUTHKIT_CONF_PATH}")
        parser = configparser.ConfigParser()
        parser.read_string(
            f"[{SLEUTHKIT_SECTION}]\n{SLEUTHKIT_CONF_PATH.read_text(encoding='utf-8')}"
        )
        return parser

    log.step(f"No Sleuth Kit config at {SLEUTHKIT_CONF_PATH}")
    parser = configparser.ConfigParser()
    parser.read_string(f"[{SLEUTHKIT_SECTION}]\n")
    return parser


def config_text(
    config: configparser.ConfigParser,
    section: str,
    key: str,
    default: str = "",
) -> str:
    if not config.has_option(section, key):
        return default
    return config.get(section, key).strip()


def config_bool(
    config: configparser.ConfigParser,
    section: str,
    key: str,
    *,
    default: bool = False,
) -> bool:
    if not config.has_option(section, key):
        return default
    return config.getboolean(section, key, fallback=default)


def normalize_secret(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def configured_target_device(settings: configparser.ConfigParser) -> Path | None:
    raw = config_text(settings, SLEUTHKIT_SECTION, "TARGET_DEVICE")
    if not raw:
        return None
    return Path(raw)


def configured_bitlocker(settings: configparser.ConfigParser) -> bool:
    return config_bool(settings, SLEUTHKIT_SECTION, "BITLOCKER", default=False)


def recovery_password_from_conf(settings: configparser.ConfigParser) -> str | None:
    if not settings.has_option(SLEUTHKIT_SECTION, "BITLOCKER_RECOVERY_PASSWORD"):
        return None
    raw = settings.get(SLEUTHKIT_SECTION, "BITLOCKER_RECOVERY_PASSWORD").strip()
    if not raw or raw.lower() in NONE_VALUES:
        return None
    return normalize_secret(raw)


def recovery_password(settings: configparser.ConfigParser) -> str | None:
    env_password = os.environ.get("BITLOCKER_RECOVERY_PASSWORD", "").strip()
    if env_password:
        return env_password
    return recovery_password_from_conf(settings)


def require_bitlocker_password(
    settings: configparser.ConfigParser,
    *,
    mount_point: Path | None = None,
) -> str:
    password = recovery_password(settings)
    if password:
        return password

    password_hint = (
        "Set the BITLOCKER_RECOVERY_PASSWORD environment variable or "
        f"BITLOCKER_RECOVERY_PASSWORD in {SLEUTHKIT_CONF_PATH}."
    )
    if mount_point is not None:
        raise RuntimeError(
            f"Mount point `{mount_point}` is backed by a BitLocker-encrypted volume, "
            f"but no recovery password was found. {password_hint}"
        )

    raise RuntimeError(
        f"Target is BitLocker-encrypted but no recovery password was found. "
        f"{password_hint}"
    )


def diskutil_info(path: Path) -> dict[str, str]:
    try:
        result = subprocess.run(
            ["diskutil", "info", str(path)],
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


def mount_source_for_path(mount_point: Path) -> Path | None:
    try:
        result = subprocess.run(
            ["mount"],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return None

    if result.returncode != 0:
        return None

    resolved = mount_point.resolve(strict=False)
    candidates = {str(resolved), str(mount_point)}
    for line in result.stdout.splitlines():
        if " on " not in line:
            continue
        source, _, remainder = line.partition(" on ")
        mount_target, _, _ = remainder.partition(" (")
        mount_target = mount_target.strip()
        try:
            normalized_target = str(Path(mount_target).resolve(strict=False))
        except OSError:
            normalized_target = mount_target
        if mount_target not in candidates and normalized_target not in candidates:
            continue
        source = source.strip()
        if source:
            return Path(source)
    return None


def dislocker_block_device_from_process(log: KirbyLogger) -> Path | None:
    try:
        result = subprocess.run(
            ["ps", "aux"],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return None

    if result.returncode != 0:
        return None

    for line in result.stdout.splitlines():
        if "dislocker-fuse" not in line:
            continue
        match = re.search(r"-V\s+(\S+)", line)
        if not match:
            continue
        device = Path(match.group(1))
        log.step(f"Found dislocker-fuse block device from process list: {device}")
        return device

    return None


def is_dislocker_backed_mount(mount_point: Path) -> bool:
    source = mount_source_for_path(mount_point)
    if source is None:
        return False
    return source.name == DISLOCKER_FILE_NAME or "dislocker" in str(source).lower()


def device_from_mount_point(
    mount_point: Path,
    log: KirbyLogger,
) -> ResolvedTarget | None:
    if is_dislocker_backed_mount(mount_point):
        device = dislocker_block_device_from_process(log)
        if device is None:
            log.step(
                f"Mount point `{mount_point}` is backed by dislocker-file, "
                "but no dislocker-fuse block device was found in the process list"
            )
            return None

        log.step(f"Resolved dislocker-backed mount `{mount_point}` to `{device}`")
        return ResolvedTarget(
            device=device,
            bitlocker=True,
            password=None,
            source="mount point (dislocker)",
        )

    info = diskutil_info(mount_point)
    device_node = info.get("Device Node", "").strip()
    if device_node:
        device = Path(device_node)
        if is_block_device(device):
            log.step(f"Resolved mount point `{mount_point}` to `{device}` via diskutil")
            return ResolvedTarget(
                device=device,
                bitlocker=False,
                password=None,
                source="mount point (diskutil)",
            )

    device_identifier = info.get("Device Identifier", "").strip()
    if device_identifier:
        device = Path(f"/dev/{device_identifier}")
        if is_block_device(device):
            log.step(
                f"Resolved mount point `{mount_point}` to `{device}` "
                "via diskutil device identifier"
            )
            return ResolvedTarget(
                device=device,
                bitlocker=False,
                password=None,
                source="mount point (diskutil)",
            )

    return None


def resolve_from_config(
    settings: configparser.ConfigParser,
    log: KirbyLogger,
) -> ResolvedTarget | None:
    device = configured_target_device(settings)
    if device is None:
        return None

    bitlocker = configured_bitlocker(settings)
    password = recovery_password(settings) if bitlocker else None
    if bitlocker and password is None:
        require_bitlocker_password(settings)

    log.step(f"Using TARGET_DEVICE from {SLEUTHKIT_CONF_PATH}: {device}")
    return ResolvedTarget(
        device=device,
        bitlocker=bitlocker,
        password=password,
        source="sleuthkit.conf",
    )


def resolve_from_target(
    target: Path,
    settings: configparser.ConfigParser,
    log: KirbyLogger,
) -> ResolvedTarget:
    if is_disk_image_or_device(target):
        bitlocker = configured_bitlocker(settings)
        password = recovery_password(settings) if bitlocker else None
        if bitlocker and password is None:
            require_bitlocker_password(settings)

        log.step(f"Using device from -t target: {target}")
        return ResolvedTarget(
            device=target,
            bitlocker=bitlocker,
            password=password,
            source="-t target",
        )

    if not target.is_dir():
        raise RuntimeError(
            f"Target `{target}` is not a mount point, block device, or disk image."
        )

    resolved = device_from_mount_point(target, log)
    if resolved is None:
        raise RuntimeError(
            f"Could not determine the block device for mount point `{target}`.\n"
            f"Set TARGET_DEVICE in {SLEUTHKIT_CONF_PATH}. "
            "If the volume is BitLocker-encrypted via dislocker, also set "
            "BITLOCKER = true and BITLOCKER_RECOVERY_PASSWORD."
        )

    if resolved.bitlocker:
        password = require_bitlocker_password(settings, mount_point=target)
        return ResolvedTarget(
            device=resolved.device,
            bitlocker=True,
            password=password,
            source=resolved.source,
        )

    return resolved


def resolve_analysis_target(
    target: Path,
    settings: configparser.ConfigParser,
    log: KirbyLogger,
    *,
    prefer_config_device: bool = False,
) -> ResolvedTarget:
    if prefer_config_device:
        configured = resolve_from_config(settings, log)
        if configured is not None:
            return configured
        return resolve_from_target(target, settings, log)

    try:
        return resolve_from_target(target, settings, log)
    except RuntimeError:
        configured = resolve_from_config(settings, log)
        if configured is not None:
            return configured
        raise


def find_tool(name: str, prefix: Path, log: KirbyLogger) -> str:
    local_tool = prefix / "bin" / name
    if local_tool.is_file():
        log.step(f"Using {name} from {local_tool}")
        return str(local_tool)

    found = shutil.which(name)
    if found:
        log.step(f"Using {name} from PATH: {found}")
        return found

    raise FileNotFoundError(
        f"{name} not found. Build Sleuth Kit with "
        f"{ROOT / 'modules/analysis/sleuthkit-mactime/build_sleuthkit.sh'}"
    )


def privileged_command(command: list[str], log: KirbyLogger) -> list[str]:
    if os.geteuid() == 0:
        return command

    log.step("Requesting elevated privileges via sudo for raw device access")
    return ["sudo", *command]


def tsk_requires_sudo(device: Path) -> bool:
    return is_block_device(device)


def run_tsk_command(
    command: list[str],
    log: KirbyLogger,
    *,
    privileged: bool = True,
) -> subprocess.CompletedProcess[str]:
    args = privileged_command(command, log) if privileged else command
    log.step(f"Running: {' '.join(args)}")
    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        check=False,
    )
