"""VirusTotal analysis module — look up hashes for files flagged by scan modules."""

from __future__ import annotations

import configparser
import hashlib
import json
import os
import sqlite3
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from kirby_flagged import backfill_flagged_hashes, load_flagged
from kirby_index import load_hash_cache, lookup_sha256
from kirby_log import KirbyLogger
from kirby_tool_errors import check_vt_payload

MODULE_DIR = Path(__file__).resolve().parent
ENV_PATH = ROOT / ".env"
VT_API_URL = "https://www.virustotal.com/api/v3/files/{sha256}"
VT_GUI_URL = "https://www.virustotal.com/gui/file/{sha256}"
ALERT_SEVERITIES = frozenset({"SEVERITY_MEDIUM", "SEVERITY_HIGH"})
CONFIG_SECTION = "virustotal"


def load_config(config_path: Path) -> configparser.ConfigParser:
    parser = configparser.ConfigParser()
    parser.read_string(f"[{CONFIG_SECTION}]\n{config_path.read_text(encoding='utf-8')}")
    return parser


def project_path(config: configparser.ConfigParser, key: str) -> Path:
    value = config.get(CONFIG_SECTION, key)
    path = Path(value)
    if path.is_absolute():
        return path
    return ROOT / path


def load_dotenv(path: Path) -> None:
    if not path.is_file():
        return

    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key:
            os.environ.setdefault(key, value)


def read_flagged_files(
    flagged_csv: Path,
    log: KirbyLogger,
) -> list[tuple[Path, list[str], str]]:
    if not flagged_csv.is_file():
        log.step(f"No flagged file list at {flagged_csv}")
        return []

    flagged = load_flagged(flagged_csv)
    log.step(f"Loaded {len(flagged)} path(s) from {flagged_csv}")

    files: list[tuple[Path, list[str], str]] = []
    for path_str, (tools, sha256) in sorted(flagged.items()):
        path = Path(path_str)
        if not path.is_file():
            log.step(f"Skipping missing file: {path}")
            continue
        files.append((path, tools, sha256))
    log.step(f"Found {len(files)} existing flagged file(s) to analyze")
    return files


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def hash_files(
    files: list[tuple[Path, list[str], str]],
    log: KirbyLogger,
    *,
    sha256_hashes_path: Path,
) -> list[tuple[Path, list[str], str]]:
    hash_cache = load_hash_cache(sha256_hashes_path)
    hashed: list[tuple[Path, list[str], str]] = []
    from_csv = 0
    from_cache = 0
    computed = 0

    for path, tools, cached_sha256 in log.progress(
        files,
        total=len(files),
        desc="Hashing flagged files",
        unit="file",
    ):
        digest = cached_sha256
        if digest:
            from_csv += 1
        else:
            digest = lookup_sha256(path, hash_cache)
            if digest:
                from_cache += 1
            else:
                try:
                    digest = sha256_file(path)
                    computed += 1
                except OSError as exc:
                    log.step(f"Skipping {path}: {exc}")
                    continue

        hashed.append((path, tools, digest))

    log.step(
        f"SHA-256 sources: {from_csv} from flagged.csv, "
        f"{from_cache} from hash cache, {computed} computed on disk"
    )
    return hashed


def write_hashes_file(
    hashed: list[tuple[Path, list[str], str]],
    destination: Path,
    log: KirbyLogger,
) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    lines = [f"{digest}\t{path}" for path, _, digest in hashed]
    destination.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    log.step(f"Wrote {len(lines)} hash(es) to {destination}")


def init_cache(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(db_path)
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS vt_cache (
            sha256 TEXT PRIMARY KEY,
            response_json TEXT NOT NULL,
            fetched_at TEXT NOT NULL
        )
        """
    )
    connection.commit()
    return connection


def cache_get(connection: sqlite3.Connection, sha256: str) -> dict | None:
    row = connection.execute(
        "SELECT response_json FROM vt_cache WHERE sha256 = ?",
        (sha256,),
    ).fetchone()
    if row is None:
        return None
    return json.loads(row[0])


def cache_put(connection: sqlite3.Connection, sha256: str, payload: dict) -> None:
    connection.execute(
        """
        INSERT INTO vt_cache (sha256, response_json, fetched_at)
        VALUES (?, ?, ?)
        ON CONFLICT(sha256) DO UPDATE SET
            response_json = excluded.response_json,
            fetched_at = excluded.fetched_at
        """,
        (sha256, json.dumps(payload), datetime.now(timezone.utc).isoformat()),
    )
    connection.commit()


def virustotal_api_key() -> str:
    load_dotenv(ENV_PATH)
    api_key = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError(
            "VIRUSTOTAL_API_KEY is not set; add it to .env or the environment"
        )
    return api_key


def fetch_virustotal_report(
    sha256: str,
    api_key: str,
    *,
    delay_seconds: float,
    last_request_at: list[float],
) -> dict:
    if delay_seconds > 0 and last_request_at[0] > 0:
        elapsed = time.monotonic() - last_request_at[0]
        remaining = delay_seconds - elapsed
        if remaining > 0:
            time.sleep(remaining)

    request = urllib.request.Request(
        VT_API_URL.format(sha256=sha256),
        headers={
            "Accept": "application/json",
            "x-apikey": api_key,
        },
        method="GET",
    )

    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            last_request_at[0] = time.monotonic()
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        last_request_at[0] = time.monotonic()
        body = exc.read().decode("utf-8", errors="replace")
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            payload = {"error": {"code": exc.reason, "message": body}}
        payload["_http_status"] = exc.code
        return payload


def lookup_virustotal(
    sha256: str,
    connection: sqlite3.Connection,
    api_key: str,
    *,
    delay_seconds: float,
    last_request_at: list[float],
    log: KirbyLogger,
) -> tuple[dict, bool]:
    cached = cache_get(connection, sha256)
    if cached is not None:
        return cached, True

    log.step(f"Querying VirusTotal for {sha256}")
    payload = fetch_virustotal_report(
        sha256,
        api_key,
        delay_seconds=delay_seconds,
        last_request_at=last_request_at,
    )
    cache_put(connection, sha256, payload)
    return payload, False


def vt_attributes(payload: dict) -> dict:
    if "error" in payload:
        return {}
    data = payload.get("data")
    if not isinstance(data, dict):
        return {}
    attributes = data.get("attributes")
    if not isinstance(attributes, dict):
        return {}
    return attributes


def vt_error(payload: dict) -> str | None:
    error = payload.get("error")
    if isinstance(error, dict):
        code = error.get("code")
        if code:
            return str(code)
    status = payload.get("_http_status")
    if status is not None:
        return f"HTTP {status}"
    return None


def format_query_summary(
    path: Path,
    sha256: str,
    payload: dict,
    *,
    source: str,
) -> str:
    error = vt_error(payload)
    if error:
        return f"{path} | {sha256} | {source} | error: {error}"

    attributes = vt_attributes(payload)
    severity = attributes.get("threat_severity_level") or "unknown"
    verdict = attributes.get("threat_verdict") or "unknown"
    stats = attributes.get("last_analysis_stats")
    detections = "n/a"
    if isinstance(stats, dict):
        malicious = stats.get("malicious", 0)
        total = sum(value for value in stats.values() if isinstance(value, int))
        detections = f"{malicious}/{total}" if total else str(malicious)

    status = "FLAGGED" if severity in ALERT_SEVERITIES else "ok"
    label = attributes.get("meaningful_name") or attributes.get("type_description")
    label_part = f" | {label}" if label else ""

    return (
        f"{path} | {sha256} | {source} | {severity} | {verdict} | "
        f"{detections} detections | {status}{label_part}"
    )


def log_query_summary(
    log: KirbyLogger,
    path: Path,
    sha256: str,
    payload: dict,
    *,
    source: str,
) -> None:
    summary = format_query_summary(path, sha256, payload, source=source)
    if not log.verbose:
        return

    try:
        from tqdm import tqdm

        tqdm.write(f"[{log.prefix}] {summary}", file=sys.stderr)
    except ImportError:
        print(f"[{log.prefix}] {summary}", file=sys.stderr, flush=True)


def format_timestamp(value: object) -> str:
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        )
    return str(value)


def format_json_field(value: object) -> str:
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True, indent=2)
    return str(value)


def vt_field_lines(attributes: dict) -> list[str]:
    fields = [
        ("threat_severity_level", attributes.get("threat_severity_level")),
        ("threat_severity", attributes.get("threat_severity")),
        ("threat_verdict", attributes.get("threat_verdict")),
        ("type_description", attributes.get("type_description")),
        ("type_tag", attributes.get("type_tag")),
        ("meaningful_name", attributes.get("meaningful_name")),
        ("md5", attributes.get("md5")),
        ("sha1", attributes.get("sha1")),
        ("sha256", attributes.get("sha256")),
        ("first_submission_date", attributes.get("first_submission_date")),
        ("last_analysis_date", attributes.get("last_analysis_date")),
        ("last_analysis_stats", attributes.get("last_analysis_stats")),
        ("threat_severity_data", attributes.get("threat_severity_data")),
        ("tags", attributes.get("tags")),
        ("popular_threat_classification", attributes.get("popular_threat_classification")),
        ("total_votes", attributes.get("total_votes")),
    ]

    lines: list[str] = []
    for name, value in fields:
        if value is None or value == "" or value == {} or value == []:
            continue
        if name.endswith("_date"):
            rendered = format_timestamp(value)
        elif isinstance(value, (dict, list)):
            rendered = format_json_field(value)
            lines.append(f"- **{name}:**")
            lines.extend(["", "```json", rendered, "```"])
            continue
        else:
            rendered = str(value)
        lines.append(f"- **{name}:** `{rendered}`")
    return lines


def format_result_section(
    path: Path,
    sha256: str,
    scan_tools: list[str],
    payload: dict,
) -> str:
    lines = [
        f"### `{path}`",
        "",
        f"- **hash:** `{sha256}`",
        f"- **flagged_by:** `{', '.join(scan_tools)}`",
    ]

    error = vt_error(payload)
    if error:
        lines.append(f"- **VirusTotal error:** `{error}`")
    else:
        lines.extend(vt_field_lines(vt_attributes(payload)))
        lines.append(f"- **VirusTotal:** {VT_GUI_URL.format(sha256=sha256)}")

    lines.append("")
    return "\n".join(lines)


def format_report(
    target: Path | None,
    flagged_csv: Path,
    hashes_path: Path,
    cache_path: Path,
    flagged_count: int,
    result_sections: list[str],
) -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    if target is None:
        target_label = f"(not provided; using `{flagged_csv}`)"
    else:
        target_label = f"`{target}`"
    lines = [
        "# VirusTotal Analysis Report",
        "",
        "## Analysis Info",
        "",
        f"- **Target:** {target_label}",
        f"- **Flagged file list:** `{flagged_csv}`",
        f"- **Hashes file:** `{hashes_path}`",
        f"- **Cache database:** `{cache_path}`",
        f"- **Flagged files analyzed:** {flagged_count}",
        f"- **Analysis time:** {timestamp}",
        "",
    ]

    if result_sections:
        lines.extend([f"## Results ({len(result_sections)})", ""])
        lines.extend(result_sections)
    else:
        lines.extend(["## Results", "", "No flagged files to analyze."])

    return "\n".join(lines)


def run(
    target: Path | None,
    output: Path,
    config: Path,
    *,
    verbose: bool = True,
    flagged_csv: Path | None = None,
    hashes_output: Path | None = None,
    file_list: Path | None = None,
    force_errors: bool = False,
) -> None:
    log = KirbyLogger(verbose, prefix="virustotal")
    log.step(f"Loading config from {config}")
    settings = load_config(config)

    flagged_csv_path = flagged_csv or project_path(settings, "flagged_csv")
    hashes_path = hashes_output or project_path(settings, "hashes_output")
    sha256_hashes_path = (
        file_list.parent / "sha256_hashes"
        if file_list is not None
        else flagged_csv_path.parent / "sha256_hashes"
    )
    cache_path = project_path(settings, "cache_db")
    delay_seconds = settings.getfloat(CONFIG_SECTION, "api_delay_seconds", fallback=15.0)
    api_key = virustotal_api_key()

    flagged_files = read_flagged_files(flagged_csv_path, log)
    if flagged_csv is None:
        backfilled = backfill_flagged_hashes(
            flagged_csv_path,
            hashes_path=sha256_hashes_path,
        )
        if backfilled:
            log.step(f"Backfilled {backfilled} SHA-256 hash(es) in {flagged_csv_path}")
            flagged_files = read_flagged_files(flagged_csv_path, log)
    hashed = hash_files(flagged_files, log, sha256_hashes_path=sha256_hashes_path)
    write_hashes_file(hashed, hashes_path, log)

    connection = init_cache(cache_path)
    last_request_at = [0.0]
    result_sections: list[str] = []

    for path, scan_tools, digest in log.progress(
        hashed,
        total=len(hashed),
        desc="Checking VirusTotal",
        unit="hash",
    ):
        payload, from_cache = lookup_virustotal(
            digest,
            connection,
            api_key,
            delay_seconds=delay_seconds,
            last_request_at=last_request_at,
            log=log,
        )
        if not check_vt_payload(
            payload,
            context=f"VirusTotal lookup failed for {digest}",
            force_errors=force_errors,
        ):
            continue
        source = "cache" if from_cache else "API"
        log_query_summary(log, path, digest, payload, source=source)
        result_sections.append(format_result_section(path, digest, scan_tools, payload))

    connection.close()

    log.step(f"Writing report to {output}")
    report = format_report(
        target=target,
        flagged_csv=flagged_csv_path,
        hashes_path=hashes_path,
        cache_path=cache_path,
        flagged_count=len(hashed),
        result_sections=result_sections,
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(report, encoding="utf-8")
