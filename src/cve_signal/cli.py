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
    parser.add_argument(
        "--test-post",
        action="store_true",
        help="Send the --cve alerts to Telegram as a marked test, without saving state.",
    )
    parser.add_argument(
        "--refresh-scores",
        action="store_true",
        help="Reply to posted CVEs whose CISA KEV / EPSS changed (with --dry-run: preview).",
    )
    parser.add_argument(
        "--refresh-limit",
        type=_positive_int,
        help="Send at most this many refresh updates in one run.",
    )
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
        print(f"CVE source: {config.feeds.cve_source}")
        print(f"EPSS source: {config.feeds.epss_source}")
        print(f"CISA KEV source: {config.feeds.kev_source}")
        for name, value in (
            ("CIRCL CVE feed", config.feeds.circl_cve_url),
            ("NVD", config.feeds.nvd_url),
            ("Exploit-DB", config.feeds.exploitdb_csv_url),
            ("EPSS", config.feeds.epss_url),
            ("CISA KEV", config.feeds.kev_url),
            ("CVE.org + CISA Vulnrichment", config.feeds.cveorg_url),
            ("GitHub Advisory Database", config.feeds.ghsa_url),
            ("OSV.dev", config.feeds.osv_url),
            ("BDU FSTEC", config.feeds.bdu_url),
            ("EUVD (ENISA)", config.feeds.euvd_url),
            ("CIRCL Vulnerability-Lookup", config.feeds.circl_url),
            ("GitHub", "https://api.github.com/search/repositories"),
        ):
            print(f"{name}: {value or 'disabled'}")
        return 0
    if args.refresh_scores:
        from cve_signal.refresh import run_refresh

        try:
            result = run_refresh(
                config, args.state, dry_run=args.dry_run, limit=args.refresh_limit
            )
        except Exception as error:
            print(f"cve-signal failed: {error}", file=sys.stderr)
            return 1
        print(
            f"refresh: posted={result.posted} changed={result.changed} sent={result.sent} "
            f"kev_new={result.kev_new} epss_new={result.epss_new}"
        )
        return 0
    if not args.dry_run and args.format != "telegram-html":
        print("cve-signal failed: --format is only available with --dry-run", file=sys.stderr)
        return 2
    if args.test_post and (args.dry_run or not args.cve):
        print("cve-signal failed: --test-post needs --cve and no --dry-run", file=sys.stderr)
        return 2
    if not args.dry_run and not args.test_post and (args.cve or args.explain):
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
            test_post=args.test_post,
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
