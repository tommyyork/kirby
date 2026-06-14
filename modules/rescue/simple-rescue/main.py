"""simple-rescue module — copy user-owned documents from a Windows volume after macro checks."""

from __future__ import annotations

import configparser
import importlib.util
import shutil
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from kirby_flagged import record_flagged
from kirby_index import mount_entry, resolve_mount_point, scan_root_relative
from kirby_log import KirbyLogger
from kirby_report import format_scan_report_header, scan_timestamp
from kirby_tool_errors import check_subprocess

MODULE_DIR = Path(__file__).resolve().parent
MODULE_SECTION = "simple-rescue"
MRAPTOR_MODULE_PATH = ROOT / "modules" / "scan" / "mraptor" / "main.py"


class VolumeType(str, Enum):
    WINDOWS = "windows"
    MACOS = "macos"
    UNKNOWN = "unknown"


class InclusionCategory(str, Enum):
    DOCUMENT = "document"
    SPREADSHEET = "spreadsheet"
    IMAGE = "image"
    EMAIL = "email"


@dataclass(frozen=True)
class RescueCandidate:
    path: Path
    username: str
    category: InclusionCategory
    relative_path: Path


@dataclass(frozen=True)
class ExcludedFile:
    candidate: RescueCandidate
    mraptor_output: str
    exit_code: int


@dataclass(frozen=True)
class RescueResult:
    copied: list[RescueCandidate]
    excluded: list[ExcludedFile]
    skipped_mraptor: list[RescueCandidate]


def load_config(config_path: Path) -> configparser.ConfigParser:
    parser = configparser.ConfigParser()
    parser.read_string(f"[{MODULE_SECTION}]\n{config_path.read_text(encoding='utf-8')}")
    return parser


def project_path(config: configparser.ConfigParser, key: str) -> Path:
    value = config.get(MODULE_SECTION, key)
    path = Path(value)
    if path.is_absolute():
        return path
    return ROOT / path


def config_list(config: configparser.ConfigParser, key: str) -> list[str]:
    raw = config.get(MODULE_SECTION, key, fallback="")
    return [item.strip() for item in raw.split(",") if item.strip()]


def config_bool(config: configparser.ConfigParser, key: str, default: bool = True) -> bool:
    if not config.has_option(MODULE_SECTION, key):
        return default
    return config.getboolean(MODULE_SECTION, key, fallback=default)


def normalize_extensions(raw_items: list[str]) -> set[str]:
    extensions: set[str] = set()
    for item in raw_items:
        ext = item.strip().lower()
        if not ext:
            continue
        if not ext.startswith("."):
            ext = f".{ext}"
        extensions.add(ext)
    return extensions


def rescue_extensions(config: configparser.ConfigParser) -> dict[InclusionCategory, set[str]]:
    return {
        InclusionCategory.DOCUMENT: normalize_extensions(
            config_list(config, "document_extensions")
        ),
        InclusionCategory.SPREADSHEET: normalize_extensions(
            config_list(config, "spreadsheet_extensions")
        ),
        InclusionCategory.IMAGE: normalize_extensions(
            config_list(config, "image_extensions")
        ),
        InclusionCategory.EMAIL: normalize_extensions(
            config_list(config, "email_extensions")
        ),
    }


def extension_category(
    path: Path,
    categories: dict[InclusionCategory, set[str]],
) -> InclusionCategory | None:
    ext = path.suffix.lower()
    for category, extensions in categories.items():
        if ext in extensions:
            return category
    return None


def windows_layout_score(volume_root: Path) -> int:
    score = 0
    if (volume_root / "Windows").is_dir():
        score += 2
    if (volume_root / "Windows" / "System32").is_dir():
        score += 2
    if (volume_root / "Users").is_dir():
        score += 1
    if (volume_root / "Program Files").is_dir():
        score += 1
    if (volume_root / "ProgramData").is_dir():
        score += 1
    return score


def macos_layout_score(volume_root: Path) -> int:
    score = 0
    if (volume_root / "System" / "Library").is_dir():
        score += 2
    if (volume_root / "Applications").is_dir():
        score += 1
    if (volume_root / "Library").is_dir() and not (volume_root / "Windows").is_dir():
        score += 1
    if (volume_root / "private" / "etc").is_dir():
        score += 1
    return score


def filesystem_suggests_windows(filesystem: str) -> bool:
    normalized = filesystem.casefold()
    return any(
        token in normalized
        for token in ("ntfs", "exfat", "fat32", "msdos", "fuseblk", "tuxera")
    )


def filesystem_suggests_macos(filesystem: str) -> bool:
    normalized = filesystem.casefold()
    return any(token in normalized for token in ("apfs", "hfs", "macos", "mfs"))


def detect_volume_type(volume_root: Path, *, filesystem: str = "") -> VolumeType:
    """Classify the mounted volume using layout markers at the mount root."""
    windows_score = windows_layout_score(volume_root)
    macos_score = macos_layout_score(volume_root)

    if windows_score >= 2 and windows_score >= macos_score:
        return VolumeType.WINDOWS
    if macos_score >= 2 and macos_score > windows_score:
        return VolumeType.MACOS
    if filesystem_suggests_windows(filesystem) and (volume_root / "Users").is_dir():
        return VolumeType.WINDOWS
    if filesystem_suggests_macos(filesystem) and macos_score >= 1:
        return VolumeType.MACOS
    if (volume_root / "Windows" / "System32").is_dir():
        return VolumeType.WINDOWS
    if (volume_root / "System" / "Library").is_dir():
        return VolumeType.MACOS
    return VolumeType.UNKNOWN


def profile_is_in_scope(profile_dir: Path, target: Path) -> bool:
    target_resolved = target.resolve(strict=False)
    profile_resolved = profile_dir.resolve(strict=False)
    try:
        if profile_resolved == target_resolved:
            return True
        if profile_resolved.is_relative_to(target_resolved):
            return True
        if target_resolved.is_relative_to(profile_resolved):
            return True
    except ValueError:
        target_str = str(target_resolved)
        profile_str = str(profile_resolved)
        return (
            profile_str == target_str
            or profile_str.startswith(f"{target_str}/")
            or target_str.startswith(f"{profile_str}/")
        )
    return False


def read_file_list(path: Path, log: KirbyLogger) -> list[Path]:
    if not path.is_file():
        raise FileNotFoundError(f"File list not found: {path}")

    log.step(f"Reading file inventory from {path}")
    files: list[Path] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        entry = line.strip()
        if entry:
            files.append(Path(entry))
    log.step(f"Loaded {len(files)} paths from inventory")
    return files


def discover_windows_users(
    volume_root: Path,
    target: Path,
    config: configparser.ConfigParser,
    log: KirbyLogger,
) -> list[str]:
    users_rel = config.get(MODULE_SECTION, "users_dir", fallback="Users")
    skip_profiles = {
        name.casefold() for name in config_list(config, "skip_user_profiles")
    }
    users_dir = volume_root / users_rel
    if not users_dir.is_dir():
        log.step(f"Users directory not found at {users_dir}")
        return []

    profiles: list[str] = []
    for profile_dir in sorted(users_dir.iterdir()):
        if not profile_dir.is_dir():
            continue
        if profile_dir.name.casefold() in skip_profiles:
            continue
        if not profile_is_in_scope(profile_dir, target):
            continue
        ntuser = profile_dir / "NTUSER.DAT"
        if not ntuser.is_file():
            log.step(f"Skipping {profile_dir.name}: no NTUSER.DAT hive")
            continue
        profiles.append(profile_dir.name)

    log.step(f"Found {len(profiles)} non-default Windows user profile(s) in scope")
    return profiles


def profile_prefix(volume_root: Path, users_rel: str, username: str) -> Path:
    return (volume_root / users_rel / username).resolve(strict=False)


def relative_profile_path(path: Path, profile_root: Path) -> Path | None:
    try:
        return path.resolve(strict=False).relative_to(profile_root)
    except ValueError:
        return None


def path_is_skipped(relative: Path, skip_paths: list[str]) -> bool:
    rel_posix = relative.as_posix().casefold()
    for skip in skip_paths:
        skip_posix = skip.replace("\\", "/").strip("/").casefold()
        if not skip_posix:
            continue
        if rel_posix == skip_posix or rel_posix.startswith(f"{skip_posix}/"):
            return True
    return False


def path_in_user_content(relative: Path, content_dirs: list[str]) -> bool:
    if not content_dirs:
        return True

    rel_posix = relative.as_posix().casefold()
    for content_dir in content_dirs:
        content_posix = content_dir.replace("\\", "/").strip("/").casefold()
        if not content_posix:
            continue
        if rel_posix == content_posix or rel_posix.startswith(f"{content_posix}/"):
            return True
    return False


def file_owned_by_profile_user(path: Path, profile_root: Path) -> bool:
    """Treat files under a profile directory as owned by that profile's user."""
    try:
        path.resolve(strict=False).relative_to(profile_root)
    except ValueError:
        return False
    return path.is_file()


def collect_rescue_candidates(
    files: list[Path],
    volume_root: Path,
    target: Path,
    config: configparser.ConfigParser,
    usernames: list[str],
    log: KirbyLogger,
) -> list[RescueCandidate]:
    users_rel = config.get(MODULE_SECTION, "users_dir", fallback="Users")
    skip_paths = config_list(config, "skip_profile_paths")
    content_dirs = config_list(config, "user_content_dirs")
    categories = rescue_extensions(config)

    candidates: list[RescueCandidate] = []
    for username in usernames:
        profile_root = profile_prefix(volume_root, users_rel, username)
        if not profile_root.is_dir():
            log.step(f"Profile directory missing for {username}: {profile_root}")
            continue
        if not profile_is_in_scope(profile_root, target):
            continue

        for path in files:
            if not file_owned_by_profile_user(path, profile_root):
                continue

            relative = relative_profile_path(path, profile_root)
            if relative is None:
                continue
            if path_is_skipped(relative, skip_paths):
                continue
            if not path_in_user_content(relative, content_dirs):
                continue

            category = extension_category(path, categories)
            if category is None:
                continue

            candidates.append(
                RescueCandidate(
                    path=path,
                    username=username,
                    category=category,
                    relative_path=relative,
                )
            )

    candidates.sort(key=lambda item: (item.username.lower(), str(item.path).lower()))
    log.step(f"Selected {len(candidates)} rescue candidate file(s)")
    return candidates


def write_candidate_list(candidates: list[RescueCandidate], destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    lines = [str(candidate.path) for candidate in candidates]
    destination.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def load_mraptor_module():
    spec = importlib.util.spec_from_file_location("kirby_mraptor", MRAPTOR_MODULE_PATH)
    if spec is None or spec.loader is None:
        raise ImportError(f"Unable to load mraptor module: {MRAPTOR_MODULE_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def mraptor_eligible_candidates(
    candidates: list[RescueCandidate],
    mraptor_config: Path,
    log: KirbyLogger,
) -> tuple[list[RescueCandidate], list[RescueCandidate]]:
    mraptor = load_mraptor_module()
    settings = mraptor.load_config(mraptor_config)
    extensions = mraptor.eligible_extensions(settings)

    eligible: list[RescueCandidate] = []
    skipped: list[RescueCandidate] = []
    for candidate in candidates:
        path = candidate.path
        if path.suffix.lower() not in extensions:
            skipped.append(candidate)
            continue
        if mraptor.is_recycle_bin_sidecar(path):
            skipped.append(candidate)
            continue
        if not mraptor.has_valid_office_header(path):
            skipped.append(candidate)
            continue
        eligible.append(candidate)

    log.step(
        f"mraptor scope: {len(eligible)} VBA-capable file(s), "
        f"{len(skipped)} not scanned for macros"
    )
    return eligible, skipped


def format_mraptor_output(result) -> str:
    lines: list[str] = []
    stdout = (result.stdout or "").strip()
    stderr = (result.stderr or "").strip()
    if stdout:
        lines.append(stdout)
    if stderr:
        lines.extend(["", "stderr:", stderr])
    if not lines:
        return "suspicious macro behavior"
    lines.append("")
    lines.append(f"mraptor exit code: {result.returncode}")
    return "\n".join(lines)


def scan_candidates_with_mraptor(
    candidates: list[RescueCandidate],
    mraptor_config: Path,
    settings: configparser.ConfigParser,
    log: KirbyLogger,
    *,
    force_errors: bool = False,
) -> tuple[list[RescueCandidate], list[ExcludedFile]]:
    mraptor = load_mraptor_module()
    show_matches = config_bool(settings, "mraptor_show_matches", default=True)
    eligible, _ = mraptor_eligible_candidates(candidates, mraptor_config, log)
    if not eligible:
        return candidates, []

    command = mraptor.find_mraptor(log)
    safe = list(candidates)
    excluded: list[ExcludedFile] = []
    malicious_paths: set[Path] = set()

    for candidate in log.progress(
        eligible,
        total=len(eligible),
        desc="Running mraptor",
        unit="file",
    ):
        result = mraptor.run_mraptor(command, candidate.path, show_matches=show_matches)
        if not check_subprocess(
            result,
            context=f"mraptor failed for {candidate.path}",
            allowed_returncodes=frozenset({0, mraptor.MRAPTOR_SUSPICIOUS_EXIT}),
            force_errors=force_errors,
        ):
            continue
        if mraptor.is_mraptor_suspicious(result):
            summary = (result.stdout or "").strip().splitlines()
            detail = summary[0] if summary else "suspicious macro behavior"
            log.flag(f"{candidate.path} — {detail}")
            excluded.append(
                ExcludedFile(
                    candidate=candidate,
                    mraptor_output=format_mraptor_output(result),
                    exit_code=result.returncode,
                )
            )
            malicious_paths.add(candidate.path)

    safe = [candidate for candidate in candidates if candidate.path not in malicious_paths]
    log.step(f"mraptor excluded {len(excluded)} file(s) from rescue")
    return safe, excluded


def rescue_output_root(output: Path) -> Path:
    return output.parent / "simple-rescue"


def destination_for_candidate(rescue_root: Path, candidate: RescueCandidate) -> Path:
    return rescue_root / candidate.username / candidate.relative_path


def copy_rescue_files(
    candidates: list[RescueCandidate],
    rescue_root: Path,
    log: KirbyLogger,
) -> list[RescueCandidate]:
    copied: list[RescueCandidate] = []
    for candidate in log.progress(
        candidates,
        total=len(candidates),
        desc="Copying files",
        unit="file",
    ):
        destination = destination_for_candidate(rescue_root, candidate)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(candidate.path, destination)
        copied.append(candidate)
    log.step(f"Copied {len(copied)} file(s) under {rescue_root}")
    return copied


def category_label(category: InclusionCategory) -> str:
    return {
        InclusionCategory.DOCUMENT: "document",
        InclusionCategory.SPREADSHEET: "spreadsheet",
        InclusionCategory.IMAGE: "image",
        InclusionCategory.EMAIL: "email",
    }[category]


def format_candidate_row(candidate: RescueCandidate) -> str:
    return (
        f"| `{candidate.relative_path.as_posix()}` | {candidate.username} | "
        f"{category_label(candidate.category)} | `{candidate.path}` |"
    )


def format_excluded_files_section(excluded: list[ExcludedFile]) -> list[str]:
    lines = ["## Excluded files", ""]
    if not excluded:
        lines.extend(
            [
                "No files were excluded. mraptor did not flag any rescue candidates "
                "as suspicious.",
                "",
            ]
        )
        return lines

    lines.extend(
        [
            "These rescue candidates were **not copied** because mraptor reported "
            "suspicious macro behavior:",
            "",
        ]
    )
    for index, item in enumerate(excluded, start=1):
        candidate = item.candidate
        lines.extend(
            [
                f"### {index}. `{candidate.relative_path.as_posix()}`",
                "",
                f"- **User:** {candidate.username}",
                f"- **Category:** {category_label(candidate.category)}",
                f"- **Source path:** `{candidate.path}`",
                "",
                "**mraptor output:**",
                "",
                "```",
                item.mraptor_output,
                "```",
                "",
            ]
        )
    return lines


def format_rescue_report(
    target: Path,
    config: configparser.ConfigParser,
    volume_type: VolumeType,
    usernames: list[str],
    result: RescueResult,
    *,
    candidate_list: Path,
    rescue_root: Path,
) -> str:
    lines = format_scan_report_header(
        "# simple-rescue Report",
        target,
        config,
        MODULE_SECTION,
    )
    lines.extend(
        [
            f"Volume type: **{volume_type.value}**",
            f"Rescue root: `{rescue_root}`",
            f"Candidate list: `{candidate_list}`",
            "",
            "## Inclusion criteria",
            "",
            "Files were selected when all of the following applied:",
            "",
            "- The mounted volume was identified as **Windows** using layout markers at the "
            "mount root (`Windows/`, `Users/`, `Program Files/`, filesystem type).",
            "- The file path is under `Users/<profile>/` for a non-default profile "
            "(profile has `NTUSER.DAT`; default profiles skipped per config).",
            "- The file is treated as owned by that profile user because it lives under "
            "their profile directory (excluding configured skip paths).",
            "- The file is under configured user content directories, or anywhere in the "
            "profile when `user_content_dirs` is empty.",
            "- The extension matches a configured document, spreadsheet, image, or email type.",
            "- VBA-capable Office files were scanned with **mraptor**; suspicious files "
            "were **not** copied.",
            "",
        ]
    )

    if usernames:
        lines.extend(
            [
                "## User profiles",
                "",
                ", ".join(f"`{name}`" for name in usernames),
                "",
            ]
        )

    lines.extend(format_excluded_files_section(result.excluded))

    lines.extend(["## Copied files", ""])
    if result.copied:
        lines.extend(
            [
                "| Relative path | User | Category | Source path |",
                "| --- | --- | --- | --- |",
                *[format_candidate_row(candidate) for candidate in result.copied],
                "",
            ]
        )
    else:
        lines.extend(["No files were copied.", ""])

    if result.skipped_mraptor:
        lines.extend(
            [
                "## Files not scanned by mraptor",
                "",
                "These copied files were not VBA-capable Office documents and were not "
                "scanned with mraptor:",
                "",
                "| Relative path | User | Category | Source path |",
                "| --- | --- | --- | --- |",
                *[format_candidate_row(candidate) for candidate in result.skipped_mraptor],
                "",
            ]
        )

    return "\n".join(lines)


def format_stub_report(
    target: Path,
    config: configparser.ConfigParser,
    volume_type: VolumeType,
) -> str:
    lines = format_scan_report_header(
        "# simple-rescue Report",
        target,
        config,
        MODULE_SECTION,
    )
    if volume_type is VolumeType.MACOS:
        lines.extend(
            [
                f"Volume type: **{volume_type.value}**",
                "",
                "macOS volume rescue is not implemented yet. No files were copied.",
                "",
            ]
        )
    else:
        lines.extend(
            [
                f"Volume type: **{volume_type.value}**",
                "",
                "Could not determine whether the target is a Windows or macOS volume. "
                "No files were copied.",
                "",
            ]
        )
    return "\n".join(lines)


def run_macos_stub(
    target: Path,
    output: Path,
    config: configparser.ConfigParser,
    log: KirbyLogger,
) -> None:
    log.step("macOS volume detected — rescue logic is not implemented yet")
    rescue_root = rescue_output_root(output)
    rescue_root.mkdir(parents=True, exist_ok=True)
    report_path = rescue_root / "report.md"
    report = format_stub_report(target, config, VolumeType.MACOS)
    report_path.write_text(report, encoding="utf-8")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        "\n".join(
            [
                "# simple-rescue Summary",
                f"Target Directory: {target}",
                f"Scan Time: {scan_timestamp()}",
                "",
                "macOS volume rescue is not implemented yet.",
                f"See `{report_path}` for details.",
                "",
            ]
        ),
        encoding="utf-8",
    )
    log.step(f"Wrote report to {report_path}")


def run_windows_rescue(
    target: Path,
    volume_root: Path,
    output: Path,
    config: configparser.ConfigParser,
    file_list_path: Path,
    flagged_csv: Path | None,
    log: KirbyLogger,
    *,
    force_errors: bool = False,
) -> None:
    usernames = discover_windows_users(volume_root, target, config, log)
    files = read_file_list(file_list_path, log)
    if not files:
        log.step(
            f"No paths in {file_list_path}; rescue cannot select files. "
            "Re-run Kirby against the mount point or user profile so tmp/<name>/all_files "
            "is populated (check for volume cache mismatches in startup diagnostics)."
        )
    candidates = collect_rescue_candidates(
        files,
        volume_root,
        target,
        config,
        usernames,
        log,
    )

    candidate_list = file_list_path.parent / "simple-rescue-candidates.txt"
    write_candidate_list(candidates, candidate_list)
    log.step(f"Wrote candidate list to {candidate_list}")

    mraptor_config = project_path(config, "mraptor_config")
    safe_candidates, excluded = scan_candidates_with_mraptor(
        candidates,
        mraptor_config,
        config,
        log,
        force_errors=force_errors,
    )

    mraptor_eligible, _ = mraptor_eligible_candidates(
        safe_candidates,
        mraptor_config,
        log,
    )
    skipped_mraptor = [
        candidate for candidate in safe_candidates if candidate not in mraptor_eligible
    ]

    if excluded and flagged_csv is not None:
        updated = record_flagged(
            [item.candidate.path for item in excluded],
            "mraptor",
            csv_path=flagged_csv,
        )
        log.step(f"Updated {updated} excluded path(s) in {flagged_csv}")

    rescue_root = rescue_output_root(output)
    rescue_root.mkdir(parents=True, exist_ok=True)
    copied = copy_rescue_files(safe_candidates, rescue_root, log)

    result = RescueResult(
        copied=copied,
        excluded=excluded,
        skipped_mraptor=skipped_mraptor,
    )
    report_path = rescue_root / "report.md"
    report = format_rescue_report(
        target=target,
        config=config,
        volume_type=VolumeType.WINDOWS,
        usernames=usernames,
        result=result,
        candidate_list=candidate_list,
        rescue_root=rescue_root,
    )
    report_path.write_text(report, encoding="utf-8")

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        "\n".join(
            [
                "# simple-rescue Summary",
                f"Target Directory: {target}",
                f"Scan Time: {scan_timestamp()}",
                "",
                f"Copied **{len(copied)}** file(s) to `{rescue_root}`.",
                f"Excluded **{len(excluded)}** file(s) after mraptor flagged suspicious macros.",
                f"See `{report_path}` for full details.",
                "",
            ]
        ),
        encoding="utf-8",
    )
    log.step(f"Wrote report to {report_path}")


def run(
    target: Path,
    output: Path,
    config: Path,
    *,
    verbose: bool = True,
    flagged_csv: Path | None = None,
    file_list: Path | None = None,
    force_errors: bool = False,
) -> None:
    log = KirbyLogger(verbose, prefix="simple-rescue")
    log.step(f"Loading config from {config}")
    settings = load_config(config)
    file_list_path = file_list or project_path(settings, "file_list")
    flagged_csv_path = flagged_csv or file_list_path.parent / "flagged.csv"

    mount_point = resolve_mount_point(target)
    scan_root = scan_root_relative(target, mount_point)
    mount = mount_entry(target)
    log.step(f"Resolved mount point {mount_point} (scan root: {scan_root})")

    volume_type = detect_volume_type(mount_point, filesystem=mount.get("filesystem", ""))
    log.step(f"Detected volume type: {volume_type.value} at {mount_point}")

    if volume_type is VolumeType.WINDOWS:
        run_windows_rescue(
            target,
            mount_point,
            output,
            settings,
            file_list_path,
            flagged_csv_path,
            log,
            force_errors=force_errors,
        )
        return

    if volume_type is VolumeType.MACOS:
        run_macos_stub(target, output, settings, log)
        return

    rescue_root = rescue_output_root(output)
    rescue_root.mkdir(parents=True, exist_ok=True)
    report_path = rescue_root / "report.md"
    report = format_stub_report(target, settings, volume_type)
    report_path.write_text(report, encoding="utf-8")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(report, encoding="utf-8")
    log.step(f"Wrote report to {report_path}")
