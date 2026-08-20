from __future__ import annotations

import argparse
from pathlib import Path

from cve_signal import __version__
from cve_signal.config import load_config


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
    lookback = args.since_hours or config.scan.lookback_hours
    print(f"cve-signal configured with a {lookback}-hour lookback")
    if args.dry_run:
        print("dry-run mode enabled")
    return 0
