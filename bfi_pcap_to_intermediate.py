#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Parse PCAP/PCAPNG captures into reusable BFI intermediate .npz files only.

This script intentionally does not generate analysis plots. Run
bfi_intermediate_to_motion_png.py, or another future analysis script, on the
saved cache directory.
"""

from __future__ import annotations

import argparse
import sys
import traceback
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from bfi_core import (
    cache_filename_for_capture,
    choose_group,
    clean_output_png_only,
    current_timestamp,
    default_batch_cache_dir,
    default_single_cache_dir,
    extract_bfi_from_pcap,
    find_capture_files,
    find_latest_capture,
    group_key_to_dict,
    mac_colon,
    parse_options_summary,
    save_intermediate_cache,
    stack_records,
)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Parse BFI from PCAP files and save intermediate .npz data only."
    )
    parser.add_argument(
        "pcap",
        nargs="?",
        default=None,
        help="Input capture file or directory. If omitted, the newest timestamped capture under --data-dir is used.",
    )
    parser.add_argument("--data-dir", default="data", help="Directory used when no input capture is supplied.")
    parser.add_argument("--out", default=None, help="Output cache directory. Directory input defaults to a sibling *_bfi_cache_<timestamp> folder.")
    parser.add_argument("--clean-output", action="store_true", help="Delete existing contents of --out before writing caches.")
    parser.add_argument("--source-sta", "--src", default="2c:cf:67:17:0a:3c", help="Target source STA MAC")
    parser.add_argument("--ap", "--ap-mac", default="08:bf:b8:95:80:04", help="Target AP MAC")
    parser.add_argument("--all-links", action="store_true", help="Ignore source/AP filter and choose the largest BFI group")
    parser.add_argument(
        "--display-filter",
        default="wlan.fc.type_subtype == 14 || wlan.fc.type_subtype == 13",
        help="Wireshark display filter. Default scans Action/Action-No-Ack management frames.",
    )
    parser.add_argument(
        "--capture-mode",
        choices=["normal", "json", "auto"],
        default="normal",
        help="PyShark mode. Default normal avoids elastic-mapping issues. Use json for HE raw fallback.",
    )
    parser.add_argument("--he-raw-offset-bytes", type=int, default=7, help="HE raw payload offset fallback")
    parser.add_argument("--force-nr", type=int, default=None, help="Force Nr if auto detection fails")
    parser.add_argument("--force-nc", type=int, default=None, help="Force Nc if auto detection fails")
    parser.add_argument("--force-subcarriers", type=int, default=None, help="Force subcarrier count, e.g., 234 for VHT 80 MHz")
    parser.add_argument("--strict", action="store_true", help="Do not zero-pad incomplete angle payloads")
    parser.add_argument("--min-packets-per-group", type=int, default=20, help="Minimum packets required for selected group")
    parser.add_argument("--max-packets", type=int, default=None, help="Debug: maximum scanned packets")
    parser.add_argument("--progress-every", type=int, default=200, help="Progress print interval")
    parser.add_argument("--verbose", action="store_true", help="Print parse tracebacks")
    return parser


def summarize_groups(groups: Dict[Any, List[Any]]) -> List[Dict[str, Any]]:
    return [
        {
            "source": k.source_hex12,
            "source_colon": mac_colon(k.source_hex12),
            "ap": k.ap_hex12,
            "ap_colon": mac_colon(k.ap_hex12),
            "protocol": k.protocol,
            "Nr": k.nr,
            "Nc": k.nc,
            "n_subcarriers": k.n_subcarriers,
            "bandwidth": k.bw,
            "grouping": k.grouping,
            "n_packets": len(v),
        }
        for k, v in sorted(groups.items(), key=lambda kv: len(kv[1]), reverse=True)
    ]


def parse_capture_to_cache(
    pcap_path: Path,
    cache_path: Path,
    args: argparse.Namespace,
) -> Dict[str, Any]:
    run_args = argparse.Namespace(**vars(args))
    run_args.pcap = str(pcap_path)

    groups, run_summary = extract_bfi_from_pcap(run_args)
    run_summary["cache_root"] = str(cache_path.parent)
    run_summary["parse_options"] = parse_options_summary(run_args)
    run_summary["cache_contents"] = [
        "V_all",
        "angles_all",
        "snrs",
        "times",
        "frame_numbers",
        "packet_meta_json",
        "metadata",
    ]
    run_summary["groups_after_source_ap_filter"] = summarize_groups(groups)

    key, records = choose_group(groups, run_args)
    data = stack_records(records)
    saved_cache = save_intermediate_cache(cache_path, data, key, run_summary)
    run_summary["intermediate_cache"] = str(saved_cache)

    return {
        "run_summary": run_summary,
        "group": group_key_to_dict(key),
        "n_packets": int(data["V_all"].shape[0]),
        "V_shape": list(data["V_all"].shape),
        "cache": str(saved_cache),
    }


def print_single_summary(item: Dict[str, Any]) -> None:
    run_summary = item["run_summary"]
    print("\n=== BFI PCAP-to-intermediate complete ===")
    print(f"PCAP:       {run_summary['pcap']}")
    print(f"Cache:      {item['cache']}")
    print(f"Target STA: {run_summary['target_source_sta']}")
    print(f"Target AP:  {run_summary['target_ap']}")
    print(f"Scanned packets:     {run_summary['scanned_packets']}")
    print(f"Parsed BFI packets:  {run_summary['parsed_bfi_packets']}")
    print(f"Kept target packets: {run_summary['kept_target_packets']}")
    print(f"Selected group:      {item['group']}")
    print(f"V_all shape:         {item['V_shape']}")


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    data_dir = Path(args.data_dir).expanduser().resolve()

    if args.pcap:
        input_path = Path(args.pcap).expanduser().resolve()
    else:
        input_path = find_latest_capture(data_dir)

    if not input_path.exists():
        print(f"[ERROR] Capture path not found: {input_path}", file=sys.stderr)
        return 2

    if input_path.is_dir():
        try:
            capture_paths = find_capture_files(input_path)
        except Exception as e:
            print(f"[ERROR] {e}", file=sys.stderr)
            return 2
        if not capture_paths:
            print(f"[ERROR] No capture files found under: {input_path}", file=sys.stderr)
            return 2

        batch_ts = current_timestamp()
        cache_root = Path(args.out).expanduser().resolve() if args.out else default_batch_cache_dir(input_path, batch_ts).resolve()
        if args.clean_output:
            clean_output_png_only(cache_root)
        cache_root.mkdir(parents=True, exist_ok=True)

        print("\n=== BFI PCAP-to-intermediate batch ===")
        print(f"Input folder: {input_path}")
        print(f"Cache:        {cache_root}")
        print(f"PCAP files:   {len(capture_paths)}")

        successes: List[Dict[str, Any]] = []
        failures: List[Tuple[Path, str]] = []
        used_cache_names: set[str] = set()

        for idx, pcap_path in enumerate(capture_paths, start=1):
            cache_filename = cache_filename_for_capture(pcap_path, input_path, used_cache_names)
            print(f"\n[{idx}/{len(capture_paths)}] Processing: {pcap_path}")
            try:
                item = parse_capture_to_cache(pcap_path, cache_root / cache_filename, args)
            except Exception as e:
                failures.append((pcap_path, str(e)))
                print(f"[ERROR] {pcap_path}: {e}", file=sys.stderr)
                if getattr(args, "verbose", False):
                    traceback.print_exc()
                continue

            successes.append(item)
            print(f"Cached: {item['cache']}")

        print("\n=== Batch complete ===")
        print(f"Cache:      {cache_root}")
        print(f"Succeeded:  {len(successes)}")
        print(f"Failed:     {len(failures)}")
        if failures:
            print("Failed files:")
            for pcap_path, message in failures:
                print(f"  - {pcap_path}: {message}")
        return 2 if not successes else (1 if failures else 0)

    pcap_path = input_path
    cache_root = Path(args.out).expanduser().resolve() if args.out else default_single_cache_dir(pcap_path, data_dir).resolve()
    if args.clean_output:
        clean_output_png_only(cache_root)
    cache_root.mkdir(parents=True, exist_ok=True)

    try:
        cache_filename = cache_filename_for_capture(pcap_path, None, set())
        item = parse_capture_to_cache(pcap_path, cache_root / cache_filename, args)
    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        if getattr(args, "verbose", False):
            traceback.print_exc()
        return 2

    print_single_summary(item)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
