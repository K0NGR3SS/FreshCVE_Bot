from __future__ import annotations

import argparse
from pathlib import Path
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
    parser.add_argument("--since-hours", type=int)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    config = load_config(args.config)
    try:
        result = run_scan(
            config,
            args.state,
            lookback_hours=args.since_hours,
            dry_run=args.dry_run,
        )
    except Exception as error:
        print(f"cve-signal failed: {error}", file=sys.stderr)
        return 1

    print(
        f"fetched={result.fetched} matched={result.matched} "
        f"notified={result.notified}"
    )
    return 0
