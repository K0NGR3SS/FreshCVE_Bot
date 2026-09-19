from __future__ import annotations

import argparse
from pathlib import Path
import re
import sys

from cve_signal import __version__
from cve_signal.config import load_config
from cve_signal.pipeline import run_scan


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cve-signal",
        description="Monitor high-severity web and cloud CVEs.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--config", type=Path, default=Path("config.toml"))
    parser.add_argument("--state", type=Path, default=Path("data/state.sqlite3"))
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--since-hours", type=_positive_int)
    parser.add_argument(
        "--cve",
        action="append",
        default=[],
        type=_cve_id,
        help="Inspect a specific CVE ID; may be repeated.",
    )
    parser.add_argument(
        "--format",
        choices=("telegram-html", "text", "json"),
        default="telegram-html",
        help="Dry-run output format.",
    )
    parser.add_argument(
        "--explain",
        action="store_true",
        help="Include internal ranking evidence and scores in dry-run output.",
    )
    parser.add_argument(
        "--sources",
        action="store_true",
        help="Print configured data sources and exit.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    config = load_config(args.config)
    if args.sources:
        for name, value in (
            ("NVD", config.feeds.nvd_url),
            ("Exploit-DB", config.feeds.exploitdb_csv_url),
            ("EPSS", config.feeds.epss_url),
            ("CISA KEV", config.feeds.kev_url),
            ("GitHub", "https://api.github.com/search/repositories"),
        ):
            print(f"{name}: {value or 'disabled'}")
        return 0
    if not args.dry_run and args.format != "telegram-html":
        print("cve-signal failed: --format is only available with --dry-run", file=sys.stderr)
        return 2
    if not args.dry_run and (args.cve or args.explain):
        print(
            "cve-signal failed: --cve and --explain require --dry-run",
            file=sys.stderr,
        )
        return 2
    try:
        result = run_scan(
            config,
            args.state,
            lookback_hours=args.since_hours,
            dry_run=args.dry_run,
            cve_ids=tuple(args.cve),
            output_format=args.format,
            explain=args.explain,
        )
    except Exception as error:
        print(f"cve-signal failed: {error}", file=sys.stderr)
        return 1

    summary_stream = sys.stderr if args.dry_run and args.format == "json" else sys.stdout
    print(
        f"fetched={result.fetched} matched={result.matched} "
        f"notified={result.notified} source_failures={result.source_failures}",
        file=summary_stream,
    )
    return 0


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return parsed


def _cve_id(value: str) -> str:
    normalized = value.upper()
    if not re.fullmatch(r"CVE-\d{4}-\d{4,}", normalized):
        raise argparse.ArgumentTypeError("must look like CVE-2026-12345")
    return normalized
