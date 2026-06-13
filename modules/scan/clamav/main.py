import configparser
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from kirby_flagged import record_flagged
from kirby_log import KirbyLogger
from kirby_report import format_scan_report_header

TOOL_NAME = "ClamAV"


def load_config(config_path: Path) -> configparser.ConfigParser:
    parser = configparser.ConfigParser()
    parser.read_string(f"[clamav]\n{config_path.read_text(encoding='utf-8')}")
    return parser


def format_report(target: Path, config: configparser.ConfigParser) -> str:
    lines = format_scan_report_header(
        "# ClamAV Scan Report",
        target,
        config,
        "clamav",
    )
    lines.extend(["## Results", "", "_Scan not yet implemented._", ""])
    return "\n".join(lines)


def run(
    target: Path,
    output: Path,
    config: Path,
    *,
    verbose: bool = True,
    flagged_csv: Path | None = None,
    file_list: Path | None = None,
) -> None:
    log = KirbyLogger(verbose, prefix="clamav")
    log.step(f"Loading config from {config}")
    settings = load_config(config)
    log.step(f"Scan target: {target}")
    flagged_csv_path = flagged_csv or (
        file_list.parent / "flagged.csv" if file_list is not None else ROOT / "tmp" / "flagged.csv"
    )
    flagged_paths: list[Path] = []
    if flagged_paths:
        updated = record_flagged(flagged_paths, TOOL_NAME, csv_path=flagged_csv_path)
        log.step(f"Updated {updated} path(s) in {flagged_csv_path}")
    log.step(f"Writing placeholder report to {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(format_report(target, settings), encoding="utf-8")
