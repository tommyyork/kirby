"""sleuthkit-mactime module — build a MAC timeline from a disk image or device via Sleuth Kit."""

from __future__ import annotations

import configparser
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta
from datetime import timezone as dt_timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from kirby_log import KirbyLogger
from kirby_target import is_block_device, is_disk_image_or_device

MODULE_DIR = Path(__file__).resolve().parent
SLEUTHKIT_CONF_PATH = MODULE_DIR / "sleuthkit.conf"
MODULE_SECTION = "sleuthkit-mactime"
SLEUTHKIT_SECTION = "sleuthkit"
NONE_VALUES = frozenset({"", "none", "null"})
DISLOCKER_FILE_NAME = "dislocker-file"


@dataclass(frozen=True)
class ResolvedTarget:
    device: Path
    bitlocker: bool
    password: str | None
    source: str


def load_config(config_path: Path, section: str) -> configparser.ConfigParser:
    parser = configparser.ConfigParser()
    parser.read_string(f"[{section}]\n{config_path.read_text(encoding='utf-8')}")
    return parser


def project_path(config: configparser.ConfigParser, section: str, key: str) -> Path | None:
    if not config.has_option(section, key):
        return None
    value = config.get(section, key).strip()
    if not value or value.lower() in NONE_VALUES:
        return None
    path = Path(value)
    if path.is_absolute():
        return path
    return ROOT / path


def config_text(
    config: configparser.ConfigParser,
    section: str,
    key: str,
    default: str = "",
) -> str:
    if not config.has_option(section, key):
        return default
    return config.get(section, key).strip()


def config_int(
    config: configparser.ConfigParser,
    section: str,
    key: str,
    default: int,
) -> int:
    if not config.has_option(section, key):
        return default
    return config.getint(section, key, fallback=default)


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


def load_sleuthkit_settings(log: KirbyLogger) -> configparser.ConfigParser:
    if SLEUTHKIT_CONF_PATH.is_file():
        log.step(f"Loading Sleuth Kit settings from {SLEUTHKIT_CONF_PATH}")
        return load_config(SLEUTHKIT_CONF_PATH, SLEUTHKIT_SECTION)

    log.step(f"No Sleuth Kit config at {SLEUTHKIT_CONF_PATH}")
    parser = configparser.ConfigParser()
    parser.read_string(f"[{SLEUTHKIT_SECTION}]\n")
    return parser


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


def recovery_password(
    settings: configparser.ConfigParser,
    *,
    conf_only: bool = False,
) -> str | None:
    if not conf_only:
        env_password = os.environ.get("BITLOCKER_RECOVERY_PASSWORD", "").strip()
        if env_password:
            return env_password

    return recovery_password_from_conf(settings)


def require_bitlocker_password(
    settings: configparser.ConfigParser,
    *,
    mount_point: Path | None = None,
    conf_only: bool = False,
) -> str:
    password = recovery_password(settings, conf_only=conf_only)
    if password:
        return password

    if mount_point is not None:
        raise RuntimeError(
            f"Mount point `{mount_point}` is backed by dislocker (BitLocker), but "
            f"BITLOCKER_RECOVERY_PASSWORD is not set in {SLEUTHKIT_CONF_PATH}."
        )

    raise RuntimeError(
        f"BITLOCKER is enabled but BITLOCKER_RECOVERY_PASSWORD is not set in "
        f"{SLEUTHKIT_CONF_PATH}."
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
    device_node = info.get("Device Node", "")
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

    device_identifier = info.get("Device Identifier", "")
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
    if bitlocker:
        log.step("BITLOCKER is enabled in sleuthkit.conf")
    else:
        log.step("BITLOCKER is disabled in sleuthkit.conf")

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
        password = require_bitlocker_password(
            settings,
            mount_point=target,
            conf_only=True,
        )
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
) -> ResolvedTarget:
    configured = resolve_from_config(settings, log)
    if configured is not None:
        return configured

    if not SLEUTHKIT_CONF_PATH.is_file() and not configured_target_device(settings):
        log.step("No TARGET_DEVICE in sleuthkit.conf; attempting to infer from -t")

    return resolve_from_target(target, settings, log)


def parse_end_date(raw: str, *, now: datetime | None = None) -> datetime:
    if raw.lower() in NONE_VALUES:
        current = now or datetime.now()
        return current.replace(microsecond=0)

    normalized = raw.replace("Z", "+00:00")
    if "T" in normalized:
        parsed = datetime.fromisoformat(normalized)
        if parsed.tzinfo is not None:
            parsed = parsed.astimezone().replace(tzinfo=None)
        return parsed.replace(microsecond=0)

    parsed = datetime.strptime(raw, "%Y-%m-%d")
    return parsed.replace(hour=23, minute=59, second=59, microsecond=0)


def compute_date_range(
    end_date_raw: str,
    duration_hours: int,
    *,
    now: datetime | None = None,
) -> tuple[datetime, datetime, str]:
    if duration_hours <= 0:
        raise ValueError("DURATION must be a positive number of hours")

    end_dt = parse_end_date(end_date_raw, now=now)
    start_dt = end_dt - timedelta(hours=duration_hours)
    mactime_range = (
        f"{start_dt.strftime('%Y-%m-%dT%H:%M:%S')}"
        f"..{end_dt.strftime('%Y-%m-%dT%H:%M:%S')}"
    )
    return start_dt, end_dt, mactime_range


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
        f"{MODULE_DIR / 'build_sleuthkit.sh'}"
    )


def privileged_command(command: list[str], log: KirbyLogger) -> list[str]:
    if os.geteuid() == 0:
        return command

    log.step("Requesting elevated privileges via sudo for raw device access")
    return ["sudo", *command]


def run_mactime_timeline(
    resolved: ResolvedTarget,
    tsk_gettimes_cmd: str,
    mactime_cmd: str,
    date_range: str,
    timezone_name: str | None,
    log: KirbyLogger,
) -> tuple[str, str]:
    gettimes_command = [tsk_gettimes_cmd]
    if resolved.bitlocker:
        if not resolved.password:
            raise RuntimeError(
                f"BITLOCKER is enabled but no recovery password is available for "
                f"{resolved.device}."
            )
        gettimes_command.extend(["-k", resolved.password])
    gettimes_command.append(str(resolved.device))
    gettimes_args = privileged_command(gettimes_command, log)
    mactime_args = [mactime_cmd, "-h"]
    if timezone_name:
        mactime_args.extend(["-z", timezone_name])
    mactime_args.append(date_range)

    log.step(f"Running tsk_gettimes on {resolved.device}")
    log.step(f"Filtering mactime output to {date_range}")

    gettimes = subprocess.Popen(
        gettimes_args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    mactime = subprocess.Popen(
        mactime_args,
        stdin=gettimes.stdout,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if gettimes.stdout is not None:
        gettimes.stdout.close()

    stdout, mactime_stderr = mactime.communicate()
    gettimes_stderr = gettimes.stderr.read() if gettimes.stderr is not None else ""
    gettimes.wait()

    if gettimes.returncode != 0:
        details = (gettimes_stderr or mactime_stderr or stdout or "").strip()
        raise RuntimeError(
            f"tsk_gettimes failed with exit code {gettimes.returncode}"
            + (f": {details}" if details else "")
        )

    if mactime.returncode != 0:
        details = (mactime_stderr or stdout or "").strip()
        raise RuntimeError(
            f"mactime failed with exit code {mactime.returncode}"
            + (f": {details}" if details else "")
        )

    return stdout, gettimes_stderr


def format_report(
    *,
    target: Path,
    resolved: ResolvedTarget,
    end_date_config: str,
    resolved_end: datetime,
    start_dt: datetime,
    duration_hours: int,
    date_range: str,
    timezone_name: str | None,
    tsk_gettimes_cmd: str,
    mactime_cmd: str,
    timeline_output: str,
    gettimes_stderr: str,
) -> str:
    timestamp = datetime.now(dt_timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = [
        "# sleuthkit-mactime Report",
        "",
        "## Analysis Info",
        "",
        f"- **Target:** `{target}`",
        f"- **Device analyzed:** `{resolved.device}`",
        f"- **Resolution source:** `{resolved.source}`",
        f"- **BitLocker:** `{resolved.bitlocker}`",
        f"- **Sleuth Kit config:** `{SLEUTHKIT_CONF_PATH}`",
        f"- **END_DATE (config):** `{end_date_config}`",
        f"- **Resolved end:** `{resolved_end.isoformat(sep=' ')}`",
        f"- **DURATION:** `{duration_hours}` hours",
        f"- **Window start:** `{start_dt.isoformat(sep=' ')}`",
        f"- **mactime range:** `{date_range}`",
        f"- **Timezone:** `{timezone_name or 'local default'}`",
        f"- **tsk_gettimes:** `{tsk_gettimes_cmd}`",
        f"- **mactime:** `{mactime_cmd}`",
        f"- **Analysis time:** {timestamp}",
        "",
        "## mactime Output",
        "",
    ]

    output = timeline_output.strip()
    if output:
        lines.extend(["```", output, "```"])
    else:
        lines.append("_No file activity in the selected time window._")

    stderr = gettimes_stderr.strip()
    if stderr:
        lines.extend(["", "## tsk_gettimes stderr", "", "```", stderr, "```"])

    lines.append("")
    return "\n".join(lines)


def run(
    target: Path,
    output: Path,
    config: Path,
    *,
    verbose: bool = True,
    force_errors: bool = False,
) -> None:
    log = KirbyLogger(verbose, prefix="sleuthkit-mactime")
    log.step(f"Loading config from {config}")
    settings = load_config(config, MODULE_SECTION)
    sleuthkit_settings = load_sleuthkit_settings(log)

    prefix = project_path(settings, MODULE_SECTION, "sleuthkit_prefix")
    if prefix is None:
        raise RuntimeError("sleuthkit_prefix is not configured")

    end_date_raw = config_text(settings, MODULE_SECTION, "END_DATE", "NONE")
    duration_hours = config_int(settings, MODULE_SECTION, "DURATION", 72)
    timezone_name = config_text(settings, MODULE_SECTION, "timezone") or None
    if timezone_name and timezone_name.lower() in NONE_VALUES:
        timezone_name = None

    start_dt, end_dt, date_range = compute_date_range(end_date_raw, duration_hours)
    log.step(f"Timeline window: {start_dt.isoformat(sep=' ')} .. {end_dt.isoformat(sep=' ')}")

    target = target.resolve(strict=False)
    resolved = resolve_analysis_target(target, sleuthkit_settings, log)

    tsk_gettimes_cmd = find_tool("tsk_gettimes", prefix, log)
    mactime_cmd = find_tool("mactime", prefix, log)

    timeline_output, gettimes_stderr = run_mactime_timeline(
        resolved=resolved,
        tsk_gettimes_cmd=tsk_gettimes_cmd,
        mactime_cmd=mactime_cmd,
        date_range=date_range,
        timezone_name=timezone_name,
        log=log,
    )

    log.step(f"Writing report to {output}")
    report = format_report(
        target=target,
        resolved=resolved,
        end_date_config=end_date_raw,
        resolved_end=end_dt,
        start_dt=start_dt,
        duration_hours=duration_hours,
        date_range=date_range,
        timezone_name=timezone_name,
        tsk_gettimes_cmd=tsk_gettimes_cmd,
        mactime_cmd=mactime_cmd,
        timeline_output=timeline_output,
        gettimes_stderr=gettimes_stderr,
    )

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(report, encoding="utf-8")
