#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Minimal smoke-test script.

Find the newest timestamped capture under --data-dir, parse it once, and save
exactly one motion graph PNG. No intermediate cache or metadata files are
written here; use bfi_pcap_to_intermediate.py for reusable parsed data.
"""

from __future__ import annotations

import argparse
import sys
import traceback
from pathlib import Path
from typing import Optional, Sequence

from bfi_core import (
    choose_group,
    clean_output_png_only,
    current_timestamp,
    extract_bfi_from_pcap,
    find_latest_capture,
    mac_colon,
    save_stacked_dataset_and_analysis,
    stack_records,
    timestamp_from_path,
)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Smoke test: parse the newest PCAP and save one motion graph PNG."
    )
    parser.add_argument("--data-dir", default=".", help="Directory tree to search for the newest timestamped capture.")
    parser.add_argument("--out", default=None, help="Output directory. Defaults to a new sibling *_motion_test_<timestamp> folder.")
    parser.add_argument("--source-sta", "--src", default="2c:cf:67:17:0a:3c", help="Target source STA MAC")
    parser.add_argument("--ap", "--ap-mac", default="08:bf:b8:95:80:04", help="Target AP MAC")
    parser.add_argument("--all-links", action="store_true", help="Ignore source/AP filter and choose the largest BFI group")
    parser.add_argument(
        "--display-filter",
        default="wlan.fc.type_subtype == 14 || wlan.fc.type_subtype == 13",
        help="Wireshark display filter. Default scans Action/Action-No-Ack management frames.",
    )
    parser.add_argument("--capture-mode", choices=["normal", "json", "auto"], default="normal")
    parser.add_argument("--he-raw-offset-bytes", type=int, default=7)
    parser.add_argument("--force-nr", type=int, default=None)
    parser.add_argument("--force-nc", type=int, default=None)
    parser.add_argument("--force-subcarriers", type=int, default=None)
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--min-packets-per-group", type=int, default=20)
    parser.add_argument("--max-packets", type=int, default=None)
    parser.add_argument("--progress-every", type=int, default=200)
    parser.add_argument("--verbose", action="store_true")
    return parser


def default_smoke_output_dir(pcap_path: Path) -> Path:
    capture_ts = timestamp_from_path(pcap_path) or pcap_path.stem
    return pcap_path.parent / f"{capture_ts}_motion_test_{current_timestamp()}"


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    try:
        pcap_path = find_latest_capture(Path(args.data_dir))
        out_root = Path(args.out).expanduser().resolve() if args.out else default_smoke_output_dir(pcap_path).resolve()
        clean_output_png_only(out_root)
        out_root.mkdir(parents=True, exist_ok=True)

        args.pcap = str(pcap_path)
        args.motion_png_filename = "motion_metrics_overview.png"

        groups, run_summary = extract_bfi_from_pcap(args)
        key, records = choose_group(groups, args)
        data = stack_records(records)
        result = save_stacked_dataset_and_analysis(key, data, out_root, args, run_summary)
    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        if getattr(args, "verbose", False):
            traceback.print_exc()
        return 2

    print("\n=== BFI motion smoke test complete ===")
    print(f"PCAP:       {pcap_path}")
    print(f"Output:     {out_root}")
    print(f"Target STA: {'ALL' if args.all_links else mac_colon(args.source_sta)}")
    print(f"Target AP:  {'ALL' if args.all_links else mac_colon(args.ap)}")
    print(f"V_all shape: {result['V_shape']}")
    print(f"Graph:      {result['motion_metrics_overview']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
