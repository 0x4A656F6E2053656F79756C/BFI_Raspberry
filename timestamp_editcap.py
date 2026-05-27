#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Convert test.pcap with editcap and store it as data/YYYYMMDD_HHMMSS.pcap."""

from __future__ import annotations

import argparse
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional, Sequence


DEFAULT_EDITCAP = "/Applications/Wireshark.app/Contents/MacOS/editcap"


def current_timestamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def unique_output_path(data_dir: Path, timestamp: str) -> Path:
    output = data_dir / f"{timestamp}.pcap"
    if not output.exists():
        return output
    for idx in range(1, 100):
        candidate = data_dir / f"{timestamp}_{idx:02d}.pcap"
        if not candidate.exists():
            return candidate
    raise RuntimeError(f"Could not create a unique output filename for timestamp {timestamp}")


def resolve_input_capture(input_arg: str, data_dir: Path) -> Path:
    input_path = Path(input_arg).expanduser()
    if input_path.is_absolute():
        return input_path.resolve()

    cwd_path = input_path.resolve()
    if cwd_path.exists():
        return cwd_path

    data_path = (data_dir / input_arg).resolve()
    if data_path.exists():
        return data_path

    raise FileNotFoundError(
        f"Input capture not found. Checked: {cwd_path} and {data_path}"
    )


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run Wireshark editcap on test.pcap and save a timestamped capture under data/."
    )
    parser.add_argument("input", nargs="?", default="test.pcap", help="Input capture file; default is test.pcap")
    parser.add_argument("--data-dir", default="data", help="Directory where timestamped captures are saved")
    parser.add_argument("--editcap", default=DEFAULT_EDITCAP, help="Path to Wireshark editcap")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    data_dir = Path(args.data_dir).expanduser().resolve()
    input_path = resolve_input_capture(args.input, data_dir)
    editcap_path = Path(args.editcap).expanduser().resolve()

    if not input_path.exists():
        raise FileNotFoundError(f"Input capture not found: {input_path}")
    if not editcap_path.exists():
        raise FileNotFoundError(f"editcap not found: {editcap_path}")

    data_dir.mkdir(parents=True, exist_ok=True)
    output_path = unique_output_path(data_dir, current_timestamp())

    cmd = [str(editcap_path), str(input_path), str(output_path)]
    subprocess.run(cmd, check=True)
    input_path.unlink()

    print(f"Input:  {input_path}")
    print(f"Output: {output_path}")
    print(f"Deleted input: {input_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
