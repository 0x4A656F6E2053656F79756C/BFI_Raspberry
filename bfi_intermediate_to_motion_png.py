#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Generate motion PNGs from parsed BFI intermediate .npz files.

This script does not parse PCAP files. It is intended as the stable starting
point for analysis-only experiments.
"""

from __future__ import annotations

import argparse
import sys
import traceback
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from bfi_core import (
    INTERMEDIATE_CACHE_SUFFIX,
    analyze_cache_to_motion_png,
    clean_output_png_only,
    current_timestamp,
    default_batch_output_dir,
    find_intermediate_files,
    motion_png_filename_for_cache,
    safe_filename_stem,
)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate motion metric PNGs from BFI intermediate .npz files."
    )
    parser.add_argument(
        "cache",
        help="Input BFI intermediate .npz file or a directory containing *_bfi_intermediate.npz files.",
    )
    parser.add_argument("--out", default=None, help="Output PNG directory. Directory input defaults to a sibling *_motion_png_<timestamp> folder.")
    parser.add_argument(
        "--analysis",
        nargs="+",
        choices=["motion", "doppler", "pca", "static", "all"],
        default=["motion"],
        help="Analysis PNG outputs to generate. Use 'all' for motion + Doppler spectrogram + CSI-ratio PCA + static drift.",
    )
    parser.add_argument("--stft-window-seconds", type=float, default=4.0, help="Window length for Doppler/STFT spectrogram.")
    parser.add_argument("--stft-step-seconds", type=float, default=0.5, help="Step size for Doppler/STFT spectrogram.")
    parser.add_argument("--max-doppler-hz", type=float, default=5.0, help="Maximum frequency shown in Doppler/STFT spectrogram.")
    parser.add_argument("--clean-output", action="store_true", help="Delete existing contents of --out before writing PNGs.")
    parser.add_argument("--verbose", action="store_true", help="Print tracebacks")
    return parser


def output_lines(result: Dict[str, object]) -> List[str]:
    lines: List[str] = []
    motion = result.get("motion_metrics_overview")
    if motion:
        lines.append(f"Motion graph:   {motion}")
    analysis_outputs = result.get("analysis_outputs")
    if isinstance(analysis_outputs, dict):
        for name, path in analysis_outputs.items():
            lines.append(f"{name}: {path}")
    return lines


def print_single_summary(item: Dict[str, object], out_root: Path) -> None:
    run_summary = item["run_summary"]
    result = item["result"]
    print("\n=== BFI intermediate-to-motion complete ===")
    print(f"Cache:       {run_summary['intermediate_cache']}")
    print(f"Source PCAP: {run_summary['pcap']}")
    print(f"Output:      {out_root}")
    print(f"Selected group: {result['group']}")
    print(f"V_all shape:    {result['V_shape']}")
    for line in output_lines(result):
        print(line)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    input_path = Path(args.cache).expanduser().resolve()

    if not input_path.exists():
        print(f"[ERROR] Intermediate path not found: {input_path}", file=sys.stderr)
        return 2

    if input_path.is_dir():
        try:
            cache_paths = find_intermediate_files(input_path)
        except Exception as e:
            print(f"[ERROR] {e}", file=sys.stderr)
            return 2
        if not cache_paths:
            print(f"[ERROR] No intermediate cache files found under: {input_path}", file=sys.stderr)
            return 2

        out_root = Path(args.out).expanduser().resolve() if args.out else default_batch_output_dir(input_path, current_timestamp()).resolve()
        if args.clean_output:
            clean_output_png_only(out_root)
        out_root.mkdir(parents=True, exist_ok=True)

        print("\n=== BFI intermediate-to-motion batch ===")
        print(f"Input folder: {input_path}")
        print(f"Output:       {out_root}")
        print(f"Cache files:  {len(cache_paths)}")

        successes: List[Dict[str, object]] = []
        failures: List[Tuple[Path, str]] = []
        used_names: set[str] = set()

        for idx, cache_path in enumerate(cache_paths, start=1):
            output_filename = motion_png_filename_for_cache(cache_path, input_path, used_names)
            print(f"\n[{idx}/{len(cache_paths)}] Loading: {cache_path}")
            try:
                item = analyze_cache_to_motion_png(cache_path, out_root, args, output_filename)
            except Exception as e:
                failures.append((cache_path, str(e)))
                print(f"[ERROR] {cache_path}: {e}", file=sys.stderr)
                if getattr(args, "verbose", False):
                    traceback.print_exc()
                continue

            successes.append(item)
            for line in output_lines(item["result"]):
                print(f"Saved: {line}")

        print("\n=== Batch complete ===")
        print(f"Output:     {out_root}")
        print(f"Succeeded:  {len(successes)}")
        print(f"Failed:     {len(failures)}")
        if failures:
            print("Failed files:")
            for cache_path, message in failures:
                print(f"  - {cache_path}: {message}")
        return 2 if not successes else (1 if failures else 0)

    if not input_path.name.endswith(INTERMEDIATE_CACHE_SUFFIX):
        print(f"[ERROR] Expected a *{INTERMEDIATE_CACHE_SUFFIX} file: {input_path}", file=sys.stderr)
        return 2

    if args.out:
        out_root = Path(args.out).expanduser().resolve()
    else:
        stem = input_path.name[:-len(INTERMEDIATE_CACHE_SUFFIX)]
        out_root = input_path.parent / f"{safe_filename_stem(stem)}_motion_png_{current_timestamp()}"

    if args.clean_output:
        clean_output_png_only(out_root)
    out_root.mkdir(parents=True, exist_ok=True)

    try:
        output_filename = motion_png_filename_for_cache(input_path, None, set())
        item = analyze_cache_to_motion_png(input_path, out_root, args, output_filename)
    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        if getattr(args, "verbose", False):
            traceback.print_exc()
        return 2

    print_single_summary(item, out_root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
