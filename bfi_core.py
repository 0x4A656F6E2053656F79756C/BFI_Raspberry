#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bfi_pcap_to_motion_png_only.py

One-file pipeline:
  PCAP/PCAPNG -> Wi-Fi 5/6 compressed BFI extraction -> source/AP filtering
  -> BFI V matrix reconstruction -> motion metrics -> motion PNG only

Default target link:
  source STA = 2c:cf:67:17:0a:3c
  AP         = 08:bf:b8:95:80:04

Install:
  pip install pyshark numpy matplotlib
  # Also install Wireshark/TShark and make sure `tshark` is on PATH.

Examples:
  python bfi_pcap_to_motion_png_only.py

  python bfi_pcap_to_motion_png_only.py test_13.pcap

  python bfi_pcap_to_motion_png_only.py data_0529

  # Reuse parsed BFI intermediate files without reparsing PCAPs.
  python bfi_pcap_to_motion_png_only.py data_0529_bfi_cache_20260529_153012

  python bfi_pcap_to_motion_png_only.py test_13.pcap --out bfi_motion_png \
      --source-sta 2c:cf:67:17:0a:3c --ap 08:bf:b8:95:80:04

  python bfi_pcap_to_motion_png_only.py test_13.pcap --out bfi_motion_png \
      --source-sta bc:45:5b:d3:b9:70 --ap 60:38:e0:bb:ee:02

Notes:
- This script intentionally defaults to pyshark normal mode, not EK mode, because some
  Windows TShark builds do not support elastic-mapping.
- For HE/Wi-Fi 6 raw fallback, try --capture-mode json and adjust --he-raw-offset-bytes.
- PCAP inputs save one parsed BFI intermediate .npz per capture. Passing that cache
  folder later skips PCAP parsing and regenerates motion PNGs directly.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import re
import sys
import traceback
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import numpy as np


def get_matplotlib_pyplot() -> Any:
    try:
        import matplotlib
        matplotlib.use("Agg")
        from matplotlib import font_manager

        available_fonts = {f.name for f in font_manager.fontManager.ttflist}
        for font_name in ["Malgun Gothic", "AppleGothic", "NanumGothic"]:
            if font_name in available_fonts:
                matplotlib.rcParams["font.family"] = font_name
                matplotlib.rcParams["axes.unicode_minus"] = False
                break
        import matplotlib.pyplot as plt
        return plt
    except Exception as exc:  # pragma: no cover
        raise RuntimeError("matplotlib is required for PNG analysis. Install with: pip install matplotlib") from exc



# -----------------------------------------------------------------------------
# Protocol constants and BFI decompression logic
# -----------------------------------------------------------------------------

# feedback_type: 0=SU, 1=MU. codebook_info is usually 0/1.
BITS_OF_PHI: Dict[str, Dict[int, Dict[int, int]]] = {
    "ac": {0: {0: 4, 1: 6}, 1: {0: 7, 1: 9}},
    "ax": {0: {0: 4, 1: 6}, 1: {0: 7, 1: 9}},
}

# VHT data subcarrier counts used by the original project. For VHT 80 MHz this is 234.
VHT_BASE_SUBCARRIERS = {0: 52, 1: 108, 2: 234, 3: 468}
HE_FULL_BW_TONE_HINTS = {0: 242, 1: 484, 2: 996, 3: 1992}
GROUPING_DIVISOR = {0: 1, 1: 2, 2: 4, 3: 8}
BW_INDEX_TO_TEXT = {0: "20", 1: "40", 2: "80", 3: "160_or_80p80"}
CAPTURE_EXTENSIONS = {".pcap", ".pcapng", ".wcap", ".cap"}
INTERMEDIATE_CACHE_SUFFIX = "_bfi_intermediate.npz"
INTERMEDIATE_CACHE_FORMAT = "bfi_motion_intermediate"
INTERMEDIATE_CACHE_VERSION = 1


class NotBFIPacket(Exception):
    """Raised internally when a candidate WLAN packet is not a BFI packet."""


@dataclass(frozen=True)
class BFIGroupKey:
    source_hex12: str
    ap_hex12: str
    protocol: str
    nr: int
    nc: int
    n_subcarriers: int
    bw: str
    grouping: int

    def folder_name(self) -> str:
        return (
            f"src_{self.source_hex12}__ap_{self.ap_hex12}__wifi_{self.protocol}__"
            f"mimo_{self.nr}x{self.nc}__sc_{self.n_subcarriers}__bw_{self.bw}__ng_{self.grouping}"
        )


@dataclass
class BFIPacketRecord:
    frame_number: int
    time: float
    source_hex12: str
    ap_hex12: str
    protocol: str
    nr: int
    nc: int
    n_subcarriers: int
    bw: str
    grouping: int
    feedback_type: int
    codebook_info: int
    bphi: int
    bpsi: int
    bfi_len_bytes: int
    payload_bits: int
    required_bits: int
    padded_bits: int
    inferred_notes: List[str] = field(default_factory=list)
    bfi_payload_hex: str = ""
    snr: Optional[np.ndarray] = None
    angles: Optional[np.ndarray] = None
    V: Optional[np.ndarray] = None

    def key(self) -> BFIGroupKey:
        return BFIGroupKey(
            source_hex12=self.source_hex12,
            ap_hex12=self.ap_hex12,
            protocol=self.protocol,
            nr=self.nr,
            nc=self.nc,
            n_subcarriers=self.n_subcarriers,
            bw=self.bw,
            grouping=self.grouping,
        )


@dataclass
class FieldStore:
    exact: Dict[str, Any]
    compact: Dict[str, Any]


def mac_to_hex12(value: Optional[Any], fallback: str = "unknown") -> str:
    """Normalize a MAC address to 12 lowercase hex chars without colons."""
    if value is None:
        return fallback
    text = value_to_text(value)
    if not text:
        return fallback
    match = re.search(r"[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}", text)
    if match:
        return match.group(0).replace(":", "").lower()
    cleaned = re.sub(r"[^0-9A-Fa-f]", "", text).lower()
    if len(cleaned) >= 12:
        return cleaned[:12]
    return fallback


def mac_colon(hex12: str) -> str:
    h = mac_to_hex12(hex12, fallback=str(hex12).replace(":", "").lower())
    if len(h) == 12 and re.fullmatch(r"[0-9a-f]{12}", h):
        return ":".join(h[i:i+2] for i in range(0, 12, 2))
    return str(hex12)


def current_timestamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def timestamp_from_path(path: Path) -> Optional[str]:
    """Extract a YYYYMMDD_HHMMSS token from a capture/result filename."""
    text = path.stem
    match = re.search(r"(20\d{6})[_-]?(\d{6})", text)
    if match:
        return f"{match.group(1)}_{match.group(2)}"
    match = re.search(r"(20\d{2})[-_](\d{2})[-_](\d{2})[-_](\d{2})[-_](\d{2})[-_](\d{2})", text)
    if match:
        y, mo, d, h, mi, s = match.groups()
        return f"{y}{mo}{d}_{h}{mi}{s}"
    return None


def find_latest_capture(data_dir: Path) -> Path:
    data_dir = data_dir.expanduser().resolve()
    if not data_dir.exists():
        raise FileNotFoundError(f"Data directory not found: {data_dir}")

    candidates = find_capture_files(data_dir)
    if not candidates:
        raise FileNotFoundError(f"No capture files found under: {data_dir}")

    return max(candidates, key=capture_sort_key)


def find_capture_files(root_dir: Path) -> List[Path]:
    root_dir = root_dir.expanduser().resolve()
    if not root_dir.exists():
        raise FileNotFoundError(f"Capture path not found: {root_dir}")
    if not root_dir.is_dir():
        raise NotADirectoryError(f"Capture path is not a directory: {root_dir}")
    candidates = [
        p for p in root_dir.rglob("*")
        if p.is_file() and p.suffix.lower() in CAPTURE_EXTENSIONS
    ]
    return sorted(candidates, key=capture_sort_key)


def find_intermediate_files(root_dir: Path) -> List[Path]:
    root_dir = root_dir.expanduser().resolve()
    if not root_dir.exists():
        raise FileNotFoundError(f"Intermediate path not found: {root_dir}")
    if not root_dir.is_dir():
        raise NotADirectoryError(f"Intermediate path is not a directory: {root_dir}")
    return sorted(
        [p for p in root_dir.rglob(f"*{INTERMEDIATE_CACHE_SUFFIX}") if p.is_file()],
        key=lambda p: str(p),
    )


def capture_sort_key(path: Path) -> Tuple[int, str, float, str]:
    ts = timestamp_from_path(path)
    stat = path.stat()
    return (1 if ts else 0, ts or "", stat.st_mtime, str(path))


def default_output_dir_for_capture(pcap_path: Path, data_dir: Path) -> Path:
    ts = timestamp_from_path(pcap_path) or current_timestamp()
    return data_dir.expanduser().resolve() / f"{ts}_result"


def default_batch_output_dir(input_dir: Path, timestamp: Optional[str] = None) -> Path:
    ts = timestamp or current_timestamp()
    return input_dir.expanduser().resolve().parent / f"{input_dir.name}_motion_png_{ts}"


def default_batch_cache_dir(input_dir: Path, timestamp: Optional[str] = None) -> Path:
    ts = timestamp or current_timestamp()
    return input_dir.expanduser().resolve().parent / f"{input_dir.name}_bfi_cache_{ts}"


def default_single_cache_dir(pcap_path: Path, data_dir: Path) -> Path:
    ts = timestamp_from_path(pcap_path) or current_timestamp()
    return data_dir.expanduser().resolve() / f"{ts}_bfi_cache"


def safe_filename_stem(text: str) -> str:
    stem = re.sub(r"[^A-Za-z0-9._-]+", "_", text).strip("._-")
    return stem or "capture"


def motion_png_filename_for_capture(pcap_path: Path, root_dir: Optional[Path], used_names: set[str]) -> str:
    try:
        if root_dir is not None:
            rel = pcap_path.resolve().relative_to(root_dir.resolve()).with_suffix("")
            raw_stem = "__".join(rel.parts)
        else:
            raw_stem = pcap_path.stem
    except ValueError:
        raw_stem = pcap_path.stem

    stem = safe_filename_stem(raw_stem)
    candidate = f"{stem}_motion_metrics_overview.png"
    if candidate not in used_names:
        used_names.add(candidate)
        return candidate

    index = 2
    while True:
        candidate = f"{stem}_{index}_motion_metrics_overview.png"
        if candidate not in used_names:
            used_names.add(candidate)
            return candidate
        index += 1


def cache_filename_for_capture(pcap_path: Path, root_dir: Optional[Path], used_names: set[str]) -> str:
    try:
        if root_dir is not None:
            rel = pcap_path.resolve().relative_to(root_dir.resolve()).with_suffix("")
            raw_stem = "__".join(rel.parts)
        else:
            raw_stem = pcap_path.stem
    except ValueError:
        raw_stem = pcap_path.stem

    stem = safe_filename_stem(raw_stem)
    candidate = f"{stem}{INTERMEDIATE_CACHE_SUFFIX}"
    if candidate not in used_names:
        used_names.add(candidate)
        return candidate

    index = 2
    while True:
        candidate = f"{stem}_{index}{INTERMEDIATE_CACHE_SUFFIX}"
        if candidate not in used_names:
            used_names.add(candidate)
            return candidate
        index += 1


def motion_png_filename_for_cache(cache_path: Path, root_dir: Optional[Path], used_names: set[str]) -> str:
    try:
        if root_dir is not None:
            rel = cache_path.resolve().relative_to(root_dir.resolve())
            raw_stem = "__".join(rel.parts)
        else:
            raw_stem = cache_path.name
    except ValueError:
        raw_stem = cache_path.name

    if raw_stem.endswith(INTERMEDIATE_CACHE_SUFFIX):
        raw_stem = raw_stem[:-len(INTERMEDIATE_CACHE_SUFFIX)]
    elif raw_stem.endswith(".npz"):
        raw_stem = raw_stem[:-4]

    return motion_png_filename_for_capture(Path(raw_stem), None, used_names)


def compact_key(key: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(key).lower())


def value_to_text(value: Any) -> str:
    """Convert a PyShark field object/list/scalar into a raw-ish string."""
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        if not value:
            return ""
        return value_to_text(value[0])
    for attr in ("raw_value", "value", "show", "showname_value"):
        try:
            v = getattr(value, attr)
            if v is not None:
                return str(v)
        except Exception:
            pass
    return str(value)


def collect_fields(packet: Any) -> FieldStore:
    exact: Dict[str, Any] = {}
    compact: Dict[str, Any] = {}

    def add(key: str, val: Any) -> None:
        if key is None:
            return
        key_l = str(key).lower()
        exact.setdefault(key_l, val)
        compact.setdefault(compact_key(key_l), val)

    try:
        frame_info = getattr(packet, "frame_info")
        for attr in ("number", "time_relative", "time_epoch", "len"):
            try:
                add(f"frame.{attr}", getattr(frame_info, attr))
            except Exception:
                pass
    except Exception:
        pass

    for layer in getattr(packet, "layers", []):
        layer_name = str(getattr(layer, "layer_name", "layer")).lower()
        for dict_attr in ("_all_fields", "_fields_dict"):
            try:
                fields_obj = getattr(layer, dict_attr)
            except Exception:
                continue
            if isinstance(fields_obj, dict):
                for k, v in fields_obj.items():
                    add(str(k), v)
                    add(f"{layer_name}.{k}", v)
            elif isinstance(fields_obj, str):
                add(layer_name, fields_obj)
                add(f"{layer_name}.{dict_attr}", fields_obj)

        try:
            for name in getattr(layer, "field_names", []):
                try:
                    v = getattr(layer, name)
                except Exception:
                    continue
                add(str(name), v)
                add(f"{layer_name}.{name}", v)
        except Exception:
            pass

    return FieldStore(exact=exact, compact=compact)


def get_field(fields: FieldStore, candidates: Sequence[str]) -> Optional[Any]:
    for cand in candidates:
        cand_l = cand.lower()
        if cand_l in fields.exact:
            return fields.exact[cand_l]
        ck = compact_key(cand_l)
        if ck in fields.compact:
            return fields.compact[ck]
    # suffix fallback for version-dependent prefixes
    for cand in candidates:
        ck = compact_key(cand)
        for key, val in fields.compact.items():
            if key.endswith(ck):
                return val
    return None


def parse_int(value: Any, default: Optional[int] = None) -> Optional[int]:
    if value is None:
        return default
    if isinstance(value, (int, np.integer)):
        return int(value)
    text = value_to_text(value)
    if not text:
        return default
    match = re.search(r"0x[0-9A-Fa-f]+|[-+]?\d+", text)
    if not match:
        return default
    token = match.group(0)
    try:
        return int(token, 16) if token.lower().startswith("0x") else int(token, 10)
    except Exception:
        return default


def bytes_from_field(value: Any) -> List[int]:
    if value is None:
        return []
    if isinstance(value, (bytes, bytearray)):
        return list(value)
    if isinstance(value, (list, tuple)):
        out: List[int] = []
        for item in value:
            if isinstance(item, int):
                out.append(item & 0xFF)
            else:
                out.extend(bytes_from_field(item))
        return out

    text = value_to_text(value).strip()
    if not text:
        return []

    if ":" in text:
        parts = [p for p in re.split(r"[:\s,]+", text) if p]
        out = []
        for p in parts:
            p = p.strip()
            if p.lower().startswith("0x"):
                p = p[2:]
            if re.fullmatch(r"[0-9A-Fa-f]{1,2}", p):
                out.append(int(p, 16))
        if out:
            return out

    if text.lower().startswith("0x"):
        text = text[2:]
    cleaned = re.sub(r"[^0-9A-Fa-f]", "", text)
    if len(cleaned) >= 2 and len(cleaned) % 2 == 0:
        try:
            return [int(cleaned[i:i+2], 16) for i in range(0, len(cleaned), 2)]
        except Exception:
            return []
    return []


def cal_snr(snr_bytes: Sequence[int]) -> List[float]:
    ret: List[float] = []
    for b in snr_bytes:
        b = int(b) & 0xFF
        signed = b if b < 128 else b - 256
        ret.append((signed + 128) * 0.25 - 10)
    return ret


def cal_num_of_angles(nr: int, nc: int) -> int:
    num = 0
    for i in range(nr - 1, max(nr - nc, 1) - 1, -1):
        for _ in range(1, i + 1):
            num += 2
    return num


def protocol_order_decode(binstr: str, bphi: int, bpsi: int, nr: int, nc: int) -> List[int]:
    angles: List[int] = []
    cur_bit = 0
    for i in range(nr - 1, max(nr - nc, 1) - 1, -1):
        for _ in range(1, i + 1):
            segment = binstr[cur_bit:cur_bit + bphi]
            angles.append(int(segment[::-1], 2) if segment else 0)
            cur_bit += bphi
        for _ in range(1, i + 1):
            segment = binstr[cur_bit:cur_bit + bpsi]
            angles.append(int(segment[::-1], 2) if segment else 0)
            cur_bit += bpsi
    return angles


def bf_decompress(angles: np.ndarray, nr: int, nc: int, bphi: int, bpsi: int) -> np.ndarray:
    angles = np.asarray(angles, dtype=float)
    dequantized_angles = np.zeros(angles.shape, dtype=float)
    angle_idx = 0

    for i in range(nr - 1, max(0, nr - nc - 1), -1):
        for _ in range(i):
            dequantized_angles[angle_idx] = (2 * angles[angle_idx] + 1) * np.pi / (2 ** bphi)
            angle_idx += 1
        for _ in range(i):
            dequantized_angles[angle_idx] = (2 * angles[angle_idx] + 1) * np.pi / (2 ** (bpsi + 2))
            angle_idx += 1

    num_angles_cnt = len(angles)
    p = min(nr - 1, nc)
    V = np.eye(nr, nc, dtype=complex)

    for i in range(p, 0, -1):
        for j in range(nr, i, -1):
            Gt = np.eye(nr, dtype=complex)
            theta = dequantized_angles[num_angles_cnt - 1]
            Gt[i - 1, i - 1] = np.cos(theta)
            Gt[i - 1, j - 1] = -np.sin(theta)
            Gt[j - 1, i - 1] = np.sin(theta)
            Gt[j - 1, j - 1] = np.cos(theta)
            num_angles_cnt -= 1
            V = Gt @ V

        D = np.eye(nr, nr, dtype=complex)
        for j in range(nr - 1, i - 1, -1):
            theta = dequantized_angles[num_angles_cnt - 1]
            D[j - 1, j - 1] = np.exp(1j * theta)
            num_angles_cnt -= 1
        V = D @ V
    return V


def bits_for_codebook(protocol: str, feedback_type: int, codebook_info: int) -> Tuple[int, int, List[str]]:
    notes: List[str] = []
    protocol = protocol.lower()
    ft = int(feedback_type) if feedback_type is not None else 0
    cb = int(codebook_info) if codebook_info is not None else 0
    if ft not in BITS_OF_PHI.get(protocol, {}):
        notes.append(f"unknown feedback_type={ft}; fallback to SU(0)")
        ft = 0
    if cb not in BITS_OF_PHI[protocol][ft]:
        notes.append(f"unknown codebook_info={cb}; fallback to codebook_info={cb & 1}")
        cb = cb & 1
    bphi = BITS_OF_PHI[protocol][ft][cb]
    return bphi, bphi - 2, notes


def expected_subcarriers(protocol: str, bw_index: Optional[int], grouping: int) -> Optional[int]:
    if bw_index is None:
        return None
    divisor = GROUPING_DIVISOR.get(int(grouping), 1)
    if protocol == "ac" and bw_index in VHT_BASE_SUBCARRIERS:
        return max(1, VHT_BASE_SUBCARRIERS[bw_index] // divisor)
    if protocol == "ax" and bw_index in HE_FULL_BW_TONE_HINTS:
        return max(1, HE_FULL_BW_TONE_HINTS[bw_index] // divisor)
    return None


def choose_subcarrier_count(available_angle_bits: int, per_subcarrier_bits: int, expected_hint: Optional[int] = None) -> int:
    if per_subcarrier_bits <= 0:
        return expected_hint or 1
    max_n = max(0, available_angle_bits // per_subcarrier_bits)
    if max_n <= 0:
        return 0
    if expected_hint and expected_hint > 0 and expected_hint <= max_n:
        leftover = available_angle_bits - expected_hint * per_subcarrier_bits
        if 0 <= leftover < per_subcarrier_bits:
            return expected_hint
    return max_n


def infer_mimo_from_payload(
    bfi_len_bytes: int,
    protocol: str,
    feedback_type: int,
    codebook_info: int,
    bw_index: Optional[int],
    grouping: int,
) -> Tuple[int, int, int, List[str]]:
    notes = ["Nr/Nc fields missing; inferred from payload length"]
    bphi, bpsi, bit_notes = bits_for_codebook(protocol, feedback_type, codebook_info)
    notes.extend(bit_notes)

    candidates: List[Tuple[float, int, int, int]] = []
    for nr in range(1, 9):
        for nc in range(1, nr + 1):
            if bfi_len_bytes <= nc:
                continue
            n_angles = cal_num_of_angles(nr, nc)
            per_bits = int((bphi + bpsi) * (n_angles / 2))
            avail_bits = (bfi_len_bytes - nc) * 8
            hint = expected_subcarriers(protocol, bw_index, grouping)
            nsc = choose_subcarrier_count(avail_bits, per_bits, hint)
            if nsc <= 0:
                continue
            required = nsc * per_bits
            leftover = avail_bits - required
            common_bonus = 0
            if nsc in {52, 54, 56, 108, 114, 117, 122, 234, 242, 245, 468, 484, 490, 996}:
                common_bonus = -5
            score = leftover + common_bonus + 0.05 * nr + 0.03 * nc
            candidates.append((score, nr, nc, nsc))

    if not candidates:
        raise ValueError("cannot infer Nr/Nc/subcarriers from payload length")
    candidates.sort(key=lambda x: x[0])
    _, nr, nc, nsc = candidates[0]
    notes.append(f"inferred Nr={nr}, Nc={nc}, n_subcarriers={nsc}")
    return nr, nc, nsc, notes


def extract_matrix_from_bfi(
    bfi_bytes: Sequence[int],
    nr: int,
    nc: int,
    n_subcarriers: int,
    bphi: int,
    bpsi: int,
    pad_incomplete: bool = True,
) -> Tuple[np.ndarray, np.ndarray, np.ndarray, int, int]:
    bfi = [int(x) & 0xFF for x in bfi_bytes]
    if len(bfi) < nc:
        raise ValueError(f"BFI payload too short: len={len(bfi)} < Nc={nc}")

    snr = np.asarray(cal_snr(bfi[:nc]), dtype=float)
    angle_payload = bfi[nc:]
    n_angles = cal_num_of_angles(nr, nc)
    angles = np.zeros((n_subcarriers, n_angles), dtype=float)
    V_all = np.zeros((n_subcarriers, nr, nc), dtype=complex)

    if n_angles == 0:
        for sc in range(n_subcarriers):
            V_all[sc] = np.eye(nr, nc, dtype=complex)
        return snr, angles, V_all, 0, 0

    num_per_angle = int(n_angles / 2)
    per_subcarrier_bits = int((bphi + bpsi) * num_per_angle)
    required_bits = int(n_subcarriers * per_subcarrier_bits)
    bfi_bin = "".join(format(byte, "08b")[::-1] for byte in angle_payload)  # LSB-first
    payload_bits = len(bfi_bin)
    padded_bits = 0
    if payload_bits < required_bits:
        if not pad_incomplete:
            raise ValueError(f"insufficient angle payload: have {payload_bits} bits, need {required_bits} bits")
        padded_bits = required_bits - payload_bits
        bfi_bin += "0" * padded_bits

    for sc in range(n_subcarriers):
        start = sc * per_subcarrier_bits
        end = start + per_subcarrier_bits
        angles[sc, :] = protocol_order_decode(bfi_bin[start:end], bphi, bpsi, nr, nc)
        V_all[sc, :, :] = bf_decompress(angles[sc, :], nr, nc, bphi, bpsi)

    return snr, angles, V_all, payload_bits, padded_bits


# -----------------------------------------------------------------------------
# PyShark field definitions
# -----------------------------------------------------------------------------

VHT_REPORT_FIELDS = [
    "wlan.vht.compressed_beamforming_report",
    "wlan_vht_compressed_beamforming_report",
    "wlan.vht.compressed_beamforming_report.feedback_matrix",
    "wlan_vht_compressed_beamforming_report_feedback_matrix",
]
VHT_NR_FIELDS = ["wlan.vht.mimo_control.nrindex", "wlan_vht_mimo_control_nrindex"]
VHT_NC_FIELDS = ["wlan.vht.mimo_control.ncindex", "wlan_vht_mimo_control_ncindex"]
VHT_BW_FIELDS = ["wlan.vht.mimo_control.chanwidth", "wlan_vht_mimo_control_chanwidth"]
VHT_FB_FIELDS = ["wlan.vht.mimo_control.feedbacktype", "wlan_vht_mimo_control_feedbacktype"]
VHT_CODEBOOK_FIELDS = ["wlan.vht.mimo_control.codebookinfo", "wlan_vht_mimo_control_codebookinfo"]
VHT_GROUPING_FIELDS = ["wlan.vht.mimo_control.grouping", "wlan_vht_mimo_control_grouping"]

HE_REPORT_FIELDS = [
    "wlan.he.mimo.beamforming_report",
    "wlan_he_mimo_beamforming_report",
    "wlan.he.mimo.beamforming_report.matrix",
    "wlan_he_mimo_beamforming_report_matrix",
]
HE_RAW_FIELDS = ["wlan_wlan_mgt_raw", "wlan_mgt_raw", "wlan.mgt_raw", "wlan.raw", "wlan_raw"]
HE_NR_FIELDS = ["wlan.he.mimo.nr_index", "wlan_he_mimo_nr_index", "wlan_wlan_he_mimo_nr_index"]
HE_NC_FIELDS = ["wlan.he.mimo.nc_index", "wlan_he_mimo_nc_index", "wlan_wlan_he_mimo_nc_index"]
HE_BW_FIELDS = ["wlan.he.mimo.bw", "wlan_he_mimo_bw", "wlan_wlan_he_mimo_bw"]
HE_FB_FIELDS = ["wlan.he.mimo.feedback_type", "wlan_he_mimo_feedback_type", "wlan_wlan_he_mimo_feedback_type"]
HE_CODEBOOK_FIELDS = ["wlan.he.mimo.codebook_info", "wlan_he_mimo_codebook_info", "wlan_wlan_he_mimo_codebook_info"]
HE_GROUPING_FIELDS = ["wlan.he.mimo.grouping", "wlan_he_mimo_grouping", "wlan_wlan_he_mimo_grouping"]
HE_REPORT_LEN_FIELDS = [
    "wlan.he.action.he_mimo_control.report_len",
    "wlan_he_action_he_mimo_control_report_len",
    "wlan_wlan_he_action_he_mimo_control_report_len",
]

SOURCE_FIELDS = ["wlan.sa", "wlan_sa", "wlan.ta", "wlan_ta", "wlan.addr", "wlan_addr"]
# VHT compressed beamforming reports in some captures use 00:00:00:00:00:00
# for addr3/BSSID; the AP/beamformer is still the receiver address.
AP_FIELDS = ["wlan.ra", "wlan_ra", "wlan.da", "wlan_da", "wlan.bssid", "wlan_bssid"]
FRAME_NUMBER_FIELDS = ["frame.number", "frame_number"]
TIME_FIELDS = ["frame.time_relative", "frame_time_relative", "frame.time_epoch", "frame_time_epoch"]


def parse_bfi_packet(packet: Any, args: argparse.Namespace) -> BFIPacketRecord:
    fields = collect_fields(packet)

    vht_report = get_field(fields, VHT_REPORT_FIELDS)
    he_report = get_field(fields, HE_REPORT_FIELDS)
    has_he_control = any(get_field(fields, cand) is not None for cand in [HE_NR_FIELDS, HE_NC_FIELDS, HE_BW_FIELDS, HE_FB_FIELDS])
    has_vht_control = any(get_field(fields, cand) is not None for cand in [VHT_NR_FIELDS, VHT_NC_FIELDS, VHT_BW_FIELDS, VHT_FB_FIELDS])

    if he_report is not None or has_he_control:
        protocol = "ax"
    elif vht_report is not None or has_vht_control:
        protocol = "ac"
    else:
        raise NotBFIPacket("no VHT/HE BFI fields")

    source_hex12 = mac_to_hex12(get_field(fields, SOURCE_FIELDS), "unknown_source")
    ap_hex12 = mac_to_hex12(get_field(fields, AP_FIELDS), "unknown_ap")
    frame_number = parse_int(get_field(fields, FRAME_NUMBER_FIELDS), 0) or 0
    time_val = get_field(fields, TIME_FIELDS)
    try:
        time_rel = float(value_to_text(time_val)) if time_val is not None else math.nan
    except Exception:
        time_rel = math.nan

    notes: List[str] = []

    if protocol == "ac":
        bfi_bytes = bytes_from_field(vht_report)
        nr_idx = parse_int(get_field(fields, VHT_NR_FIELDS), None)
        nc_idx = parse_int(get_field(fields, VHT_NC_FIELDS), None)
        bw_idx = parse_int(get_field(fields, VHT_BW_FIELDS), None)
        feedback_type = parse_int(get_field(fields, VHT_FB_FIELDS), 0) or 0
        codebook_info = parse_int(get_field(fields, VHT_CODEBOOK_FIELDS), 0) or 0
        grouping = parse_int(get_field(fields, VHT_GROUPING_FIELDS), 0) or 0
    else:
        bfi_bytes = bytes_from_field(he_report)
        if not bfi_bytes:
            raw = get_field(fields, HE_RAW_FIELDS)
            raw_bytes = bytes_from_field(raw)
            if raw_bytes and len(raw_bytes) > args.he_raw_offset_bytes:
                bfi_bytes = raw_bytes[args.he_raw_offset_bytes:]
                notes.append(f"HE report taken from raw management payload offset={args.he_raw_offset_bytes} bytes")
        report_len = parse_int(get_field(fields, HE_REPORT_LEN_FIELDS), None)
        if report_len and report_len > 0 and bfi_bytes and report_len <= len(bfi_bytes):
            bfi_bytes = bfi_bytes[:report_len]
            notes.append(f"HE report truncated by report_len={report_len}")

        nr_idx = parse_int(get_field(fields, HE_NR_FIELDS), None)
        nc_idx = parse_int(get_field(fields, HE_NC_FIELDS), None)
        bw_idx = parse_int(get_field(fields, HE_BW_FIELDS), None)
        feedback_type = parse_int(get_field(fields, HE_FB_FIELDS), 0) or 0
        codebook_info = parse_int(get_field(fields, HE_CODEBOOK_FIELDS), 0) or 0
        grouping = parse_int(get_field(fields, HE_GROUPING_FIELDS), 0) or 0

    if not bfi_bytes:
        raise NotBFIPacket(f"{protocol} BFI control found but report bytes not found")

    bphi, bpsi, bit_notes = bits_for_codebook(protocol, feedback_type, codebook_info)
    notes.extend(bit_notes)

    if nr_idx is not None and nc_idx is not None:
        nr = int(nr_idx) + 1
        nc = int(nc_idx) + 1
    else:
        nr, nc, _inferred_nsc, infer_notes = infer_mimo_from_payload(
            len(bfi_bytes), protocol, feedback_type, codebook_info, bw_idx, grouping
        )
        notes.extend(infer_notes)

    if args.force_nr is not None:
        nr = args.force_nr
        notes.append(f"Nr forced by CLI: {nr}")
    if args.force_nc is not None:
        nc = args.force_nc
        notes.append(f"Nc forced by CLI: {nc}")
    if nr < 1 or nc < 1 or nc > nr:
        raise ValueError(f"invalid MIMO structure Nr={nr}, Nc={nc}")

    n_angles = cal_num_of_angles(nr, nc)
    per_sc_bits = int((bphi + bpsi) * (n_angles / 2))
    available_angle_bits = max(0, (len(bfi_bytes) - nc) * 8)
    hint_nsc = expected_subcarriers(protocol, bw_idx, grouping)
    n_subcarriers = choose_subcarrier_count(available_angle_bits, per_sc_bits, hint_nsc)

    if args.force_subcarriers is not None:
        n_subcarriers = args.force_subcarriers
        notes.append(f"n_subcarriers forced by CLI: {n_subcarriers}")
    if n_subcarriers <= 0:
        raise ValueError(
            f"cannot determine subcarrier count: len={len(bfi_bytes)}, Nr={nr}, Nc={nc}, per_sc_bits={per_sc_bits}"
        )

    snr, angles, V, payload_bits, padded_bits = extract_matrix_from_bfi(
        bfi_bytes=bfi_bytes,
        nr=nr,
        nc=nc,
        n_subcarriers=n_subcarriers,
        bphi=bphi,
        bpsi=bpsi,
        pad_incomplete=not args.strict,
    )
    required_bits = n_subcarriers * per_sc_bits
    bw_text = BW_INDEX_TO_TEXT.get(bw_idx, str(bw_idx) if bw_idx is not None else "unknown")

    return BFIPacketRecord(
        frame_number=frame_number,
        time=time_rel,
        source_hex12=source_hex12,
        ap_hex12=ap_hex12,
        protocol=protocol,
        nr=nr,
        nc=nc,
        n_subcarriers=n_subcarriers,
        bw=bw_text,
        grouping=grouping,
        feedback_type=feedback_type,
        codebook_info=codebook_info,
        bphi=bphi,
        bpsi=bpsi,
        bfi_len_bytes=len(bfi_bytes),
        payload_bits=payload_bits,
        required_bits=required_bits,
        padded_bits=padded_bits,
        inferred_notes=notes,
        bfi_payload_hex=bytes(int(x) & 0xFF for x in bfi_bytes).hex(),
        snr=snr,
        angles=angles,
        V=V,
    )


# -----------------------------------------------------------------------------
# Extraction helpers
# -----------------------------------------------------------------------------


def open_capture(pcap_path: Path, display_filter: Optional[str], capture_mode: str) -> Any:
    try:
        import pyshark
    except Exception as e:
        raise RuntimeError(
            "pyshark is not installed. Run `pip install pyshark`, and install Wireshark/TShark."
        ) from e

    normal_kwargs = {"input_file": str(pcap_path)}
    if display_filter:
        normal_kwargs["display_filter"] = display_filter

    json_kwargs = {"input_file": str(pcap_path), "include_raw": True, "use_json": True}
    if display_filter:
        json_kwargs["display_filter"] = display_filter

    # keep_packets=False saves memory, but older pyshark may not accept it.
    normal_kwargs_keep = dict(normal_kwargs, keep_packets=False)
    json_kwargs_keep = dict(json_kwargs, keep_packets=False)

    if capture_mode == "normal":
        candidate_kwargs = [normal_kwargs_keep, normal_kwargs]
    elif capture_mode == "json":
        candidate_kwargs = [json_kwargs_keep, json_kwargs]
    else:
        candidate_kwargs = [normal_kwargs_keep, normal_kwargs, json_kwargs_keep, json_kwargs]

    last_error = None
    for kwargs in candidate_kwargs:
        try:
            return pyshark.FileCapture(**kwargs)
        except Exception as e:
            last_error = e
            continue

    raise RuntimeError(f"Could not open PCAP through pyshark/tshark. Last error: {last_error}")


def should_keep_record(rec: BFIPacketRecord, args: argparse.Namespace) -> bool:
    if args.all_links:
        return True
    target_src = mac_to_hex12(args.source_sta, "") if args.source_sta else ""
    target_ap = mac_to_hex12(args.ap, "") if args.ap else ""
    if target_src and rec.source_hex12 != target_src:
        return False
    if target_ap and rec.ap_hex12 != target_ap:
        return False
    return True


def extract_bfi_from_pcap(args: argparse.Namespace) -> Tuple[Dict[BFIGroupKey, List[BFIPacketRecord]], Dict[str, Any]]:
    pcap_path = Path(args.pcap).expanduser().resolve()
    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    skipped_reasons = Counter()
    groups: Dict[BFIGroupKey, List[BFIPacketRecord]] = defaultdict(list)
    scanned_count = 0
    parsed_count = 0
    kept_count = 0

    cap = open_capture(pcap_path, args.display_filter, args.capture_mode)
    try:
        for packet in cap:
            scanned_count += 1
            if args.max_packets is not None and scanned_count > args.max_packets:
                break
            try:
                rec = parse_bfi_packet(packet, args)
                parsed_count += 1
                if should_keep_record(rec, args):
                    groups[rec.key()].append(rec)
                    kept_count += 1
                if parsed_count % args.progress_every == 0:
                    print(
                        f"[progress] parsed {parsed_count} BFI / kept {kept_count} target-link / scanned {scanned_count} packets"
                    )
            except NotBFIPacket as e:
                skipped_reasons[str(e)] += 1
            except Exception as e:
                skipped_reasons[type(e).__name__ + ": " + str(e)[:160]] += 1
                if args.verbose:
                    print("[debug] packet parse error:", repr(e), file=sys.stderr)
                    traceback.print_exc()
    finally:
        try:
            cap.close()
        except Exception:
            pass

    summary = {
        "pcap": str(pcap_path),
        "display_filter": args.display_filter,
        "capture_mode": args.capture_mode,
        "target_source_sta": "ALL" if args.all_links else mac_colon(args.source_sta),
        "target_ap": "ALL" if args.all_links else mac_colon(args.ap),
        "scanned_packets": scanned_count,
        "parsed_bfi_packets": parsed_count,
        "kept_target_packets": kept_count,
        "groups_before_min_packet_filter": len(groups),
        "skipped_reasons_top": skipped_reasons.most_common(30),
    }
    return groups, summary


# -----------------------------------------------------------------------------
# Dataset assembly, health checks, and motion metrics
# -----------------------------------------------------------------------------


def robust_sampling_rate(times: np.ndarray) -> Tuple[float, float, float, float, float, int]:
    times = np.asarray(times, dtype=float).reshape(-1)
    valid = np.isfinite(times)
    if np.sum(valid) < 2:
        return float("nan"), float("nan"), float("nan"), float("nan"), float("nan"), 0
    t = times[valid]
    duration = float(t[-1] - t[0])
    dt = np.diff(t)
    dt = dt[np.isfinite(dt) & (dt > 0)]
    if len(dt) == 0:
        return float("nan"), float("nan"), duration, float("nan"), float("nan"), 0
    median_dt = float(np.median(dt))
    fs_median = float(1.0 / median_dt) if median_dt > 0 else float("nan")
    fs_count = float((len(t) - 1) / duration) if duration > 0 else float("nan")
    p95_dt = float(np.percentile(dt, 95))
    large_gap_count = int(np.sum(dt > 1.0))
    return fs_median, fs_count, duration, median_dt, p95_dt, large_gap_count


def moving_average(x: np.ndarray, window: int) -> np.ndarray:
    x = np.asarray(x, dtype=float)
    if window <= 1 or len(x) == 0:
        return x
    window = min(window, len(x))
    kernel = np.ones(window, dtype=float) / float(window)
    return np.convolve(x, kernel, mode="same")


def stack_records(records: List[BFIPacketRecord]) -> Dict[str, Any]:
    records = sorted(records, key=lambda r: (math.inf if np.isnan(r.time) else r.time, r.frame_number))
    V_all = np.stack([r.V for r in records], axis=0)
    angles_all = np.stack([r.angles for r in records], axis=0)
    snrs = np.stack([r.snr for r in records], axis=0)
    times = np.asarray([r.time for r in records], dtype=float)
    frame_numbers = np.asarray([r.frame_number for r in records], dtype=int)
    return {
        "records": records,
        "V_all": V_all,
        "angles_all": angles_all,
        "snrs": snrs,
        "times": times,
        "frame_numbers": frame_numbers,
        "packet_meta": packet_metadata_from_records(records),
    }


def packet_metadata_from_records(records: List[BFIPacketRecord]) -> List[Dict[str, Any]]:
    packet_meta: List[Dict[str, Any]] = []
    for idx, rec in enumerate(records):
        padding_fraction = float(rec.padded_bits / rec.required_bits) if rec.required_bits else 0.0
        packet_meta.append({
            "packet_index": int(idx),
            "frame_number": int(rec.frame_number),
            "time": float(rec.time) if np.isfinite(rec.time) else None,
            "source": rec.source_hex12,
            "source_colon": mac_colon(rec.source_hex12),
            "ap": rec.ap_hex12,
            "ap_colon": mac_colon(rec.ap_hex12),
            "protocol": rec.protocol,
            "nr": int(rec.nr),
            "nc": int(rec.nc),
            "n_subcarriers": int(rec.n_subcarriers),
            "bw": rec.bw,
            "grouping": int(rec.grouping),
            "feedback_type": int(rec.feedback_type),
            "codebook_info": int(rec.codebook_info),
            "bphi": int(rec.bphi),
            "bpsi": int(rec.bpsi),
            "bfi_len_bytes": int(rec.bfi_len_bytes),
            "payload_bits": int(rec.payload_bits),
            "required_bits": int(rec.required_bits),
            "padded_bits": int(rec.padded_bits),
            "padding_fraction": padding_fraction,
            "inferred_notes": list(rec.inferred_notes),
            "bfi_payload_hex": rec.bfi_payload_hex,
        })
    return packet_meta


def group_key_to_dict(key: BFIGroupKey) -> Dict[str, Any]:
    return {
        "source": key.source_hex12,
        "source_colon": mac_colon(key.source_hex12),
        "ap": key.ap_hex12,
        "ap_colon": mac_colon(key.ap_hex12),
        "protocol": key.protocol,
        "nr": int(key.nr),
        "nc": int(key.nc),
        "n_subcarriers": int(key.n_subcarriers),
        "bw": key.bw,
        "grouping": int(key.grouping),
    }


def group_key_from_dict(group: Dict[str, Any], V_all: Optional[np.ndarray] = None) -> BFIGroupKey:
    if V_all is not None and np.asarray(V_all).ndim == 4:
        _, n_sc, nr, nc = np.asarray(V_all).shape
    else:
        n_sc, nr, nc = 0, 0, 0
    return BFIGroupKey(
        source_hex12=mac_to_hex12(group.get("source") or group.get("source_hex12"), "unknown"),
        ap_hex12=mac_to_hex12(group.get("ap") or group.get("ap_hex12"), "unknown"),
        protocol=str(group.get("protocol", "unknown")),
        nr=int(group.get("nr", group.get("Nr", nr))),
        nc=int(group.get("nc", group.get("Nc", nc))),
        n_subcarriers=int(group.get("n_subcarriers", n_sc)),
        bw=str(group.get("bw", group.get("bandwidth", "unknown"))),
        grouping=int(group.get("grouping", 0)),
    )


def pcap_file_info(path_text: Optional[str]) -> Dict[str, Any]:
    if not path_text:
        return {}
    path = Path(path_text)
    try:
        stat = path.stat()
    except Exception:
        return {"path": str(path)}
    return {
        "path": str(path),
        "name": path.name,
        "size_bytes": int(stat.st_size),
        "mtime": datetime.fromtimestamp(stat.st_mtime).isoformat(timespec="seconds"),
    }


def parse_options_summary(args: argparse.Namespace) -> Dict[str, Any]:
    return {
        "source_sta": getattr(args, "source_sta", None),
        "ap": getattr(args, "ap", None),
        "all_links": bool(getattr(args, "all_links", False)),
        "display_filter": getattr(args, "display_filter", None),
        "capture_mode": getattr(args, "capture_mode", None),
        "he_raw_offset_bytes": getattr(args, "he_raw_offset_bytes", None),
        "force_nr": getattr(args, "force_nr", None),
        "force_nc": getattr(args, "force_nc", None),
        "force_subcarriers": getattr(args, "force_subcarriers", None),
        "strict": bool(getattr(args, "strict", False)),
        "min_packets_per_group": getattr(args, "min_packets_per_group", None),
        "max_packets": getattr(args, "max_packets", None),
    }


def save_intermediate_cache(
    cache_path: Path,
    data: Dict[str, Any],
    key: BFIGroupKey,
    run_summary: Dict[str, Any],
) -> Path:
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    metadata = {
        "format": INTERMEDIATE_CACHE_FORMAT,
        "version": INTERMEDIATE_CACHE_VERSION,
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "source_pcap": run_summary.get("pcap"),
        "source_pcap_info": pcap_file_info(run_summary.get("pcap")),
        "record_context": find_record_context(run_summary.get("pcap"), str(cache_path)),
        "group": group_key_to_dict(key),
        "run_summary": run_summary,
        "packet_meta_count": len(data.get("packet_meta", [])),
    }
    np.savez_compressed(
        cache_path,
        V_all=np.asarray(data["V_all"]),
        angles_all=np.asarray(data["angles_all"]),
        snrs=np.asarray(data["snrs"]),
        times=np.asarray(data["times"]),
        frame_numbers=np.asarray(data["frame_numbers"]),
        metadata=np.asarray(json.dumps(metadata)),
        packet_meta_json=np.asarray(json.dumps(data.get("packet_meta", []))),
    )
    return cache_path


def load_intermediate_cache(cache_path: Path) -> Tuple[BFIGroupKey, Dict[str, Any], Dict[str, Any]]:
    cache_path = cache_path.expanduser().resolve()
    if not cache_path.exists():
        raise FileNotFoundError(f"Intermediate cache not found: {cache_path}")

    with np.load(cache_path, allow_pickle=False) as npz:
        V_all = np.asarray(npz["V_all"])
        angles_all = np.asarray(npz["angles_all"]) if "angles_all" in npz else None
        snrs = np.asarray(npz["snrs"]) if "snrs" in npz else np.empty((V_all.shape[0], 0))
        times = np.asarray(npz["times"])
        frame_numbers = np.asarray(npz["frame_numbers"]) if "frame_numbers" in npz else np.arange(V_all.shape[0])
        metadata_raw = str(npz["metadata"].item()) if "metadata" in npz else "{}"
        packet_meta_raw = str(npz["packet_meta_json"].item()) if "packet_meta_json" in npz else "[]"

    metadata = json.loads(metadata_raw)
    packet_meta = json.loads(packet_meta_raw)
    if metadata.get("format") and metadata.get("format") != INTERMEDIATE_CACHE_FORMAT:
        raise ValueError(f"Unsupported intermediate cache format: {metadata.get('format')}")

    key = group_key_from_dict(metadata.get("group", {}), V_all)
    run_summary = metadata.get("run_summary", {})
    if metadata.get("record_context"):
        run_summary.setdefault("record_context", metadata.get("record_context"))
    run_summary.setdefault("pcap", metadata.get("source_pcap", str(cache_path)))
    run_summary.setdefault("cache", str(cache_path))
    run_summary.setdefault("display_filter", "cached")
    run_summary.setdefault("capture_mode", "cached")
    run_summary.setdefault("target_source_sta", group_key_to_dict(key)["source_colon"])
    run_summary.setdefault("target_ap", group_key_to_dict(key)["ap_colon"])
    run_summary.setdefault("scanned_packets", "cached")
    run_summary.setdefault("parsed_bfi_packets", int(V_all.shape[0]))
    run_summary.setdefault("kept_target_packets", int(V_all.shape[0]))

    data = {
        "V_all": V_all,
        "angles_all": angles_all,
        "snrs": snrs,
        "times": times,
        "frame_numbers": frame_numbers,
        "packet_meta": packet_meta,
    }
    return key, data, run_summary


def antenna_diagnostics(V_all: np.ndarray, phase_zero_tol: float = 1e-12) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    n_packets, n_sc, nr, nc = V_all.shape
    rows: List[Dict[str, Any]] = []
    powers: List[float] = []

    for r in range(nr):
        row = V_all[:, :, r, :]
        finite_fraction = float(np.mean(np.isfinite(row)))
        mean_power = float(np.nanmean(np.abs(row) ** 2))
        mean_abs = float(np.nanmean(np.abs(row)))
        std_abs = float(np.nanstd(np.abs(row)))
        imag_max = float(np.nanmax(np.abs(np.imag(row))))
        if n_packets >= 2:
            phase_diff = np.angle(row[1:] * np.conj(row[:-1]))
            mean_abs_phase_diff = float(np.nanmean(np.abs(phase_diff)))
            complex_diff = float(np.nanmean(np.abs(row[1:] - row[:-1])))
            magnitude_diff = float(np.nanmean(np.abs(np.abs(row[1:]) - np.abs(row[:-1]))))
        else:
            mean_abs_phase_diff = float("nan")
            complex_diff = float("nan")
            magnitude_diff = float("nan")
        powers.append(mean_power)

        likely_reference_real = (
            np.isfinite(imag_max)
            and imag_max <= phase_zero_tol
            and np.isfinite(mean_abs_phase_diff)
            and mean_abs_phase_diff <= phase_zero_tol
            and complex_diff > phase_zero_tol
        )

        if finite_fraction < 0.999:
            status, reason = "FAIL", "NaN/Inf values detected"
        elif mean_power <= 1e-12:
            status, reason = "FAIL", "near-zero row power"
        elif likely_reference_real:
            status, reason = "PASS_REFERENCE_REAL", "phase is structurally zero/reference-real; use complex/magnitude metrics"
        elif complex_diff <= phase_zero_tol and std_abs <= phase_zero_tol:
            status, reason = "WARN_STATIC", "almost no complex/magnitude variation"
        else:
            status, reason = "PASS", "ok"

        rows.append({
            "antenna_index_1based": r + 1,
            "finite_fraction": finite_fraction,
            "mean_power": mean_power,
            "mean_abs": mean_abs,
            "std_abs": std_abs,
            "imag_max_abs": imag_max,
            "mean_abs_packet_phase_diff": mean_abs_phase_diff,
            "mean_abs_packet_complex_diff": complex_diff,
            "mean_abs_packet_magnitude_diff": magnitude_diff,
            "status": status,
            "reason": reason,
        })

    positive_powers = [p for p in powers if np.isfinite(p) and p > 0]
    median_power = float(np.median(positive_powers)) if positive_powers else 0.0
    expected_rank = min(nr, nc)
    flat = V_all.reshape(n_packets * n_sc, nr, nc)
    sample_count = min(len(flat), 2000)
    rank_ok = []
    if sample_count > 0:
        idx = np.linspace(0, len(flat) - 1, sample_count, dtype=int)
        for i in idx:
            try:
                rank_ok.append(np.linalg.matrix_rank(flat[i], tol=1e-8) >= expected_rank)
            except Exception:
                rank_ok.append(False)
    rank_ok_ratio = float(np.mean(rank_ok)) if rank_ok else float("nan")
    overall_status = "PASS" if all(str(r["status"]).startswith("PASS") for r in rows) and rank_ok_ratio >= 0.95 else "WARN"
    summary = {
        "n_packets": int(n_packets),
        "n_subcarriers": int(n_sc),
        "Nr": int(nr),
        "Nc": int(nc),
        "median_antenna_row_power": median_power,
        "expected_matrix_rank": int(expected_rank),
        "rank_ok_ratio_sampled": rank_ok_ratio,
        "overall_status": overall_status,
        "note": "BFI V is a normalized steering matrix, not raw RF power/CSI amplitude.",
    }
    return rows, summary


def compute_motion_metrics(V_all: np.ndarray, angles_all: Optional[np.ndarray], times: np.ndarray) -> Tuple[np.ndarray, List[str], Dict[str, Any]]:
    n_packets, n_sc, nr, nc = V_all.shape
    if n_packets < 2:
        return np.zeros((0, 0)), [], {}

    if len(times) == n_packets and np.all(np.isfinite(times)):
        t = times[1:] - times[0]
    else:
        t = np.arange(1, n_packets, dtype=float)

    rows = [t]
    names = ["time_s"]

    phase_diff_all = np.mean(np.abs(np.angle(V_all[1:] * np.conj(V_all[:-1]))), axis=(1, 2, 3))
    complex_diff_all = np.mean(np.abs(V_all[1:] - V_all[:-1]), axis=(1, 2, 3))
    magnitude_diff_all = np.mean(np.abs(np.abs(V_all[1:]) - np.abs(V_all[:-1])), axis=(1, 2, 3))
    rows.extend([phase_diff_all, complex_diff_all, magnitude_diff_all])
    names.extend(["phase_diff_mean_abs", "complex_diff_mean_abs", "magnitude_diff_mean_abs"])

    if nr >= 2 and nc >= 1:
        rel = V_all[:, :, 0, 0] * np.conj(V_all[:, :, 1, 0])
        rel_phase_diff = np.angle(rel[1:] * np.conj(rel[:-1]))
        rel_phase_diff_mean = np.mean(np.abs(rel_phase_diff), axis=1)
        rel_complex_diff_mean = np.mean(np.abs(rel[1:] - rel[:-1]), axis=1)
        rows.extend([rel_phase_diff_mean, rel_complex_diff_mean])
        names.extend([
            "ant1_ant2_stream1_relative_phase_diff_mean_abs",
            "ant1_ant2_stream1_relative_complex_diff_mean_abs",
        ])

    if angles_all is not None and np.asarray(angles_all).ndim == 3:
        ang = np.asarray(angles_all, dtype=float)
        angle_diff = np.mean(np.abs(ang[1:] - ang[:-1]), axis=(1, 2))
        rows.append(angle_diff)
        names.append("quantized_angle_diff_mean_abs")

    arr = np.column_stack(rows)
    stats: Dict[str, Any] = {}
    for idx, name in enumerate(names[1:], start=1):
        x = arr[:, idx]
        stats[f"{name}_mean"] = float(np.nanmean(x))
        stats[f"{name}_p95"] = float(np.nanpercentile(x, 95))
        stats[f"{name}_max"] = float(np.nanmax(x))
    return arr, names, stats


def normalize_metric_series(y: np.ndarray) -> np.ndarray:
    y = np.asarray(y, dtype=float)
    if y.size == 0:
        return y
    finite = np.isfinite(y)
    if not np.any(finite):
        return np.zeros_like(y, dtype=float)
    baseline = float(np.nanpercentile(y[finite], 5))
    scale = float(np.nanpercentile(np.abs(y[finite] - baseline), 95))
    if not np.isfinite(scale) or scale <= 0:
        scale = float(np.nanpercentile(np.abs(y[finite]), 95))
    if not np.isfinite(scale) or scale <= 0:
        scale = 1.0
    return np.clip((y - baseline) / scale, 0.0, 3.0)


def compute_motion_score(metrics: np.ndarray, column_names: List[str]) -> Tuple[np.ndarray, List[str]]:
    preferred = [
        "complex_diff_mean_abs",
        "ant1_ant2_stream1_relative_complex_diff_mean_abs",
        "quantized_angle_diff_mean_abs",
    ]
    selected: List[np.ndarray] = []
    selected_names: List[str] = []
    for name in preferred:
        if name in column_names:
            idx = column_names.index(name)
            selected.append(normalize_metric_series(metrics[:, idx]))
            selected_names.append(name)

    if not selected:
        for idx, name in enumerate(column_names[1:], start=1):
            selected.append(normalize_metric_series(metrics[:, idx]))
            selected_names.append(name)
            if len(selected) >= 3:
                break

    if not selected:
        return np.zeros(metrics.shape[0], dtype=float), []
    return np.nanmean(np.column_stack(selected), axis=1), selected_names


def motion_score_source_label(score_sources: List[str]) -> str:
    labels = {
        "complex_diff_mean_abs": "complex",
        "ant1_ant2_stream1_relative_complex_diff_mean_abs": "relative complex",
        "quantized_angle_diff_mean_abs": "angle",
        "phase_diff_mean_abs": "phase",
        "magnitude_diff_mean_abs": "magnitude",
    }
    return " + ".join(labels.get(name, name) for name in score_sources) if score_sources else "motion metrics"


def read_record_text(record_path: Path) -> str:
    try:
        return record_path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return record_path.read_text(encoding="utf-8-sig")


def extract_record_items(record_text: str) -> List[str]:
    items: List[str] = []
    for line in record_text.splitlines():
        match = re.match(r"\s*\d+\.\s*(.+?)\s*$", line)
        if match:
            items.append(match.group(1))
    return items


def cache_capture_stem(cache_path: Path) -> str:
    name = cache_path.name
    if name.endswith(INTERMEDIATE_CACHE_SUFFIX):
        return name[:-len(INTERMEDIATE_CACHE_SUFFIX)]
    if name.endswith(".npz"):
        return name[:-4]
    return cache_path.stem


def unique_paths(paths: List[Path]) -> List[Path]:
    unique: List[Path] = []
    seen: set[str] = set()
    for path in paths:
        try:
            resolved = path.expanduser().resolve()
        except Exception:
            resolved = path.expanduser().absolute()
        key = str(resolved).lower()
        if key not in seen:
            unique.append(resolved)
            seen.add(key)
    return unique


def find_record_item_index(root: Path, pcap_path: Optional[Path], cache_path: Optional[Path]) -> Optional[int]:
    if pcap_path is not None:
        try:
            captures = find_capture_files(root)
            resolved = pcap_path.resolve()
            for idx, capture in enumerate(captures):
                if capture.resolve() == resolved:
                    return idx
        except Exception:
            pass

    if cache_path is not None:
        try:
            caches = find_intermediate_files(root)
            resolved_cache = cache_path.resolve()
            for idx, cache in enumerate(caches):
                if cache.resolve() == resolved_cache:
                    return idx

            target_stems = {cache_capture_stem(cache_path)}
            if pcap_path is not None:
                target_stems.add(pcap_path.stem)
            for idx, cache in enumerate(caches):
                if cache_capture_stem(cache) in target_stems:
                    return idx
        except Exception:
            pass

    return None


def find_record_context(source_pcap: Optional[str], intermediate_cache: Optional[str] = None) -> Dict[str, Any]:
    if not source_pcap and not intermediate_cache:
        return {}
    pcap_path = Path(source_pcap) if source_pcap else None
    cache_path = Path(intermediate_cache) if intermediate_cache else None
    search_roots: List[Path] = []
    if cache_path is not None:
        search_roots.extend([cache_path.parent, *cache_path.parents])
    if pcap_path is not None:
        search_roots.extend([pcap_path.parent, *pcap_path.parents])

    for root in unique_paths(search_roots):
        record_path = root / "record.md"
        if not record_path.exists():
            continue
        try:
            record_text = read_record_text(record_path)
            items = extract_record_items(record_text)
        except Exception:
            return {"record_path": str(record_path)}

        item_index = find_record_item_index(root, pcap_path, cache_path)

        item = items[item_index] if item_index is not None and item_index < len(items) else None
        return {
            "record_path": str(record_path),
            "dataset_dir": str(root),
            "item_index": item_index,
            "item": item,
            "items": items,
        }
    return {}


def classify_record_item(item: Optional[str]) -> str:
    if not item:
        return "unknown"
    if any(token in item for token in ["아무도 없음", "부재"]):
        return "absent"
    if any(token in item for token in ["덤벨", "비인체"]):
        return "nonhuman_dynamic"
    if any(token in item for token in ["방 전체", "빙글", "돌기", "걷"]):
        return "dynamic"
    if any(token in item for token in ["정적", "앉"]):
        return "seated_sequence" if "앉" in item else "static"
    return "unknown"


def experiment_spans_from_record(run_summary: Optional[Dict[str, Any]], t_max: float) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    context = {}
    if run_summary:
        context = dict(run_summary.get("record_context") or {})
        cache_path = run_summary.get("intermediate_cache") or run_summary.get("cache")
        if not context.get("item"):
            context = find_record_context(
                str(run_summary.get("pcap")) if run_summary.get("pcap") else None,
                str(cache_path) if cache_path else None,
            )
    scenario = classify_record_item(context.get("item"))
    spans: List[Dict[str, Any]] = []

    def add(start: float, end: float, label: str, kind: str) -> None:
        start = max(0.0, float(start))
        end = min(float(end), float(t_max))
        if end > start:
            spans.append({"start": start, "end": end, "label": label, "kind": kind})

    if scenario == "seated_sequence":
        add(0, 20, "Cut", "cut")
        cursor = 20.0
        for _ in range(2):
            add(cursor, cursor + 10, "Walk in", "walk_in")
            cursor += 10
            add(cursor, cursor + 20, "Seated", "static")
            cursor += 20
            add(cursor, cursor + 10, "Walk out", "walk_out")
            cursor += 10
            add(cursor, cursor + 20, "Away", "absent")
            cursor += 20
        add(cursor, cursor + 10, "Walk in", "walk_in")
    elif scenario == "static":
        add(0, t_max, "Static presence", "static")
    elif scenario == "dynamic":
        add(0, t_max, "Dynamic presence", "walk")
    elif scenario == "absent":
        add(0, t_max, "Absent", "absent")
    elif scenario == "nonhuman_dynamic":
        add(0, t_max, "Non-human motion", "nonhuman")

    context["scenario"] = scenario
    return spans, context


def draw_experiment_spans(ax: Any, spans: List[Dict[str, Any]]) -> None:
    style = {
        "walk": ("#d62728", 0.18),
        "walk_in": ("#d62728", 0.18),
        "walk_out": ("#ff7f0e", 0.18),
        "static": ("#1f77b4", 0.16),
        "absent": ("#8c8c8c", 0.10),
        "cut": ("#d0d0d0", 0.10),
        "nonhuman": ("#ff8c00", 0.16),
    }
    seen_labels: set[str] = set()
    y_top = 0.98
    for span in spans:
        color, alpha = style.get(str(span.get("kind")), ("#bbbbbb", 0.10))
        label = str(span.get("label", ""))
        ax.axvspan(float(span["start"]), float(span["end"]), color=color, alpha=alpha, linewidth=0)
        if label and label not in seen_labels:
            mid = (float(span["start"]) + float(span["end"])) / 2.0
            ax.text(
                mid,
                y_top,
                label,
                transform=ax.get_xaxis_transform(),
                ha="center",
                va="top",
                fontsize=8,
                color="#333333",
                clip_on=True,
            )
            seen_labels.add(label)


def selected_analysis_names(args: argparse.Namespace) -> set[str]:
    raw = getattr(args, "analysis", None)
    if raw is None:
        return {"motion"}
    if isinstance(raw, str):
        values = [raw]
    else:
        values = list(raw)
    selected = {str(v).lower() for v in values}
    if "all" in selected:
        return {"motion", "doppler", "pca", "static"}
    return (selected - {"features"}) or {"motion"}


def graph_time_limits(t_max: float) -> Tuple[float, float]:
    if np.isfinite(t_max) and t_max >= 120.0:
        return 20.0, 120.0
    return 0.0, max(0.0, float(t_max)) if np.isfinite(t_max) else 0.0


def analysis_stem_from_motion_filename(output_filename: str) -> str:
    path = Path(output_filename)
    stem = path.stem
    suffix = "_motion_metrics_overview"
    if stem.endswith(suffix):
        stem = stem[:-len(suffix)]
    return safe_filename_stem(stem)


def analysis_filename(output_filename: str, suffix: str, extension: str = ".png") -> str:
    return f"{analysis_stem_from_motion_filename(output_filename)}_{suffix}{extension}"


def valid_packet_times(times: np.ndarray, n_packets: int) -> np.ndarray:
    times = np.asarray(times, dtype=float).reshape(-1)
    if len(times) == n_packets and np.all(np.isfinite(times)):
        return times - times[0]
    return np.arange(n_packets, dtype=float)


def csi_ratio_matrix(V_all: np.ndarray) -> np.ndarray:
    V_all = np.asarray(V_all)
    if V_all.ndim != 4:
        raise ValueError(f"Expected V_all shape (packet, subcarrier, Nr, Nc), got {V_all.shape}")
    _, _, nr, nc = V_all.shape
    if nr >= 2 and nc >= 1:
        return V_all[:, :, 0, 0] * np.conj(V_all[:, :, 1, 0])
    return V_all[:, :, 0, 0]


def pca_components(X: np.ndarray, n_components: int = 3) -> Tuple[np.ndarray, np.ndarray]:
    X = np.asarray(X, dtype=float)
    X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
    X = X - np.mean(X, axis=0, keepdims=True)
    scale = np.std(X, axis=0, keepdims=True)
    scale[scale <= 1e-12] = 1.0
    X = X / scale
    if X.shape[0] < 2 or X.shape[1] < 1:
        return np.zeros((X.shape[0], 0)), np.zeros((0,), dtype=float)
    U, S, _ = np.linalg.svd(X, full_matrices=False)
    k = min(n_components, U.shape[1])
    scores = U[:, :k] * S[:k]
    variance = S ** 2
    explained = variance[:k] / np.sum(variance) if np.sum(variance) > 0 else np.zeros(k)
    return scores, explained


def csi_ratio_phase_pca_signal(V_all: np.ndarray) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    ratio = csi_ratio_matrix(V_all)
    phase = np.unwrap(np.angle(ratio), axis=0)
    features = phase - np.nanmean(phase, axis=0, keepdims=True)
    scores, explained = pca_components(features, n_components=3)
    if scores.shape[1] > 0:
        signal = scores[:, 0]
    else:
        signal = np.nanmean(features, axis=1)
    signal = np.asarray(signal, dtype=float)
    signal = signal - np.nanmean(signal)
    return signal, scores, explained


def stft_spectrogram(
    signal: np.ndarray,
    fs_hz: float,
    window_seconds: float,
    step_seconds: float,
) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    signal = np.asarray(signal, dtype=float).reshape(-1)
    signal = np.nan_to_num(signal, nan=0.0, posinf=0.0, neginf=0.0)
    if signal.size < 4:
        return np.zeros((0, 0)), np.zeros((0,)), np.zeros((0,))
    if not np.isfinite(fs_hz) or fs_hz <= 0:
        fs_hz = 1.0
    nperseg = max(8, int(round(window_seconds * fs_hz)))
    nperseg = min(nperseg, signal.size)
    step = max(1, int(round(step_seconds * fs_hz)))
    if nperseg < 4:
        nperseg = min(signal.size, 4)
    window = np.hanning(nperseg)
    if not np.any(window):
        window = np.ones(nperseg)

    spectra: List[np.ndarray] = []
    centers: List[float] = []
    for start in range(0, signal.size - nperseg + 1, step):
        segment = signal[start:start + nperseg]
        segment = segment - np.mean(segment)
        spec = np.abs(np.fft.rfft(segment * window)) ** 2
        spectra.append(spec)
        centers.append((start + nperseg / 2.0) / fs_hz)
    if not spectra:
        return np.zeros((0, 0)), np.zeros((0,)), np.zeros((0,))
    S = np.asarray(spectra, dtype=float).T
    freqs = np.fft.rfftfreq(nperseg, d=1.0 / fs_hz)
    return S, freqs, np.asarray(centers, dtype=float)


def static_presence_features(V_all: np.ndarray, times: np.ndarray) -> Dict[str, np.ndarray]:
    ratio = csi_ratio_matrix(V_all)
    n_packets = ratio.shape[0]
    t = valid_packet_times(times, n_packets)
    baseline_count = max(3, min(n_packets, int(round(n_packets * 0.1))))
    baseline = np.nanmean(ratio[:baseline_count], axis=0)
    baseline_norm = np.linalg.norm(baseline)
    if not np.isfinite(baseline_norm) or baseline_norm <= 1e-12:
        baseline_norm = 1.0

    drift = np.nanmean(np.abs(ratio - baseline[None, :]), axis=1)
    corr_loss = np.zeros(n_packets, dtype=float)
    for idx in range(n_packets):
        row = ratio[idx]
        row_norm = np.linalg.norm(row)
        if not np.isfinite(row_norm) or row_norm <= 1e-12:
            corr_loss[idx] = np.nan
        else:
            corr = abs(np.vdot(row, baseline)) / (row_norm * baseline_norm)
            corr_loss[idx] = 1.0 - float(np.clip(corr, 0.0, 1.0))
    return {"time_s": t, "drift": normalize_metric_series(drift), "correlation_loss": normalize_metric_series(corr_loss)}


def overlap_seconds(a0: float, a1: float, b0: float, b1: float) -> float:
    return max(0.0, min(a1, b1) - max(a0, b0))


def label_for_window(start: float, end: float, spans: List[Dict[str, Any]]) -> Tuple[str, str]:
    best: Optional[Dict[str, Any]] = None
    best_overlap = 0.0
    for span in spans:
        ov = overlap_seconds(start, end, float(span["start"]), float(span["end"]))
        if ov > best_overlap:
            best_overlap = ov
            best = span
    if best is None or best_overlap <= 0:
        return "", ""
    return str(best.get("label", "")), str(best.get("kind", ""))


def kind_for_time(t: float, spans: List[Dict[str, Any]]) -> str:
    for span in spans:
        if float(span["start"]) <= t <= float(span["end"]):
            return str(span.get("kind", ""))
    return ""


def pca_trajectory_categories(t: np.ndarray, spans: List[Dict[str, Any]]) -> List[Tuple[str, str, np.ndarray]]:
    categories = [
        ("walk_in", "Walk in", "#d62728"),
        ("walk_out", "Walk out", "#ff7f0e"),
        ("static", "Seated", "#1f77b4"),
        ("absent", "Away", "#7f7f7f"),
    ]
    kinds = np.asarray([kind_for_time(float(x), spans) for x in t], dtype=object)
    result: List[Tuple[str, str, np.ndarray]] = []
    for kind, label, color in categories:
        result.append((label, color, kinds == kind))
    return result


def plot_doppler_spectrogram(
    data: Dict[str, Any],
    out_dir: Path,
    output_filename: str,
    args: argparse.Namespace,
    run_summary: Optional[Dict[str, Any]] = None,
) -> Path:
    plt = get_matplotlib_pyplot()
    V_all = np.asarray(data["V_all"])
    times = np.asarray(data["times"])
    t = valid_packet_times(times, V_all.shape[0])
    fs_median, _, _, _, _, _ = robust_sampling_rate(times)
    if not np.isfinite(fs_median) or fs_median <= 0:
        fs_median = 1.0 / np.nanmedian(np.diff(t)) if len(t) > 1 and np.nanmedian(np.diff(t)) > 0 else 1.0
    signal, _, _ = csi_ratio_phase_pca_signal(V_all)
    window_seconds = float(getattr(args, "stft_window_seconds", 4.0))
    step_seconds = float(getattr(args, "stft_step_seconds", 0.5))
    S, freqs, centers = stft_spectrogram(signal, fs_median, window_seconds, step_seconds)
    output = out_dir / analysis_filename(output_filename, "doppler_spectrogram")

    fig, ax = plt.subplots(figsize=(11, 4.2))
    t_max = float(np.nanmax(t)) if t.size else 0.0
    x_min, x_max = graph_time_limits(t_max)
    spans, context = experiment_spans_from_record(run_summary, t_max)
    draw_experiment_spans(ax, spans)
    if S.size:
        max_freq = min(float(getattr(args, "max_doppler_hz", 5.0)), float(np.nanmax(freqs)) if freqs.size else 0.0)
        keep = freqs <= max_freq
        image = 10.0 * np.log10(S[keep] + 1e-12)
        extent = [float(centers[0]), float(centers[-1]), float(freqs[keep][0]), float(freqs[keep][-1])]
        im = ax.imshow(image, aspect="auto", origin="lower", extent=extent, cmap="magma", alpha=0.92)
        fig.colorbar(im, ax=ax, label="Power (dB)")
    ax.set_xlim(x_min, x_max)
    ax.set_xlabel("Time (s)")
    ax.set_ylabel("Frequency (Hz)")
    title = "CSI-ratio Doppler Spectrogram"
    if context.get("item"):
        title += f" - Trial {int(context['item_index']) + 1}: {context['item']}"
    ax.set_title(title, fontsize=11)
    fig.tight_layout()
    fig.savefig(output, dpi=220)
    plt.close(fig)
    return output


def plot_csi_ratio_pca(
    data: Dict[str, Any],
    out_dir: Path,
    output_filename: str,
    args: argparse.Namespace,
    run_summary: Optional[Dict[str, Any]] = None,
) -> Path:
    plt = get_matplotlib_pyplot()
    V_all = np.asarray(data["V_all"])
    times = np.asarray(data["times"])
    t = valid_packet_times(times, V_all.shape[0])
    _, scores, explained = csi_ratio_phase_pca_signal(V_all)
    output = out_dir / analysis_filename(output_filename, "csi_ratio_pca")

    fig, axes = plt.subplots(2, 1, figsize=(11, 6), sharex=False)
    t_max = float(np.nanmax(t)) if t.size else 0.0
    x_min, x_max = graph_time_limits(t_max)
    spans, context = experiment_spans_from_record(run_summary, t_max)
    ax0, ax1 = axes
    draw_experiment_spans(ax0, spans)
    for idx in range(min(3, scores.shape[1])):
        label = f"PC{idx + 1}"
        if idx < len(explained):
            label += f" ({explained[idx] * 100:.1f}%)"
        ax0.plot(t, normalize_metric_series(np.abs(scores[:, idx])), linewidth=1.2, label=label)
    ax0.set_xlim(x_min, x_max)
    ax0.set_ylabel("Normalized |PC|")
    ax0.grid(True, axis="y", alpha=0.25)
    ax0.legend(loc="upper right", fontsize=8)
    title = "CSI-ratio PCA"
    if context.get("item"):
        title += f" - Trial {int(context['item_index']) + 1}: {context['item']}"
    ax0.set_title(title, fontsize=11)

    if scores.shape[1] >= 2:
        scatter_mask = (t >= x_min) & (t <= x_max) if x_max > x_min else np.ones_like(t, dtype=bool)
        plotted = False
        for label, color, category_mask in pca_trajectory_categories(t, spans):
            mask = scatter_mask & category_mask
            if not np.any(mask):
                continue
            ax1.scatter(scores[mask, 0], scores[mask, 1], color=color, s=16, alpha=0.82, label=label)
            plotted = True
        other_mask = scatter_mask.copy()
        for _, _, category_mask in pca_trajectory_categories(t, spans):
            other_mask &= ~category_mask
        if np.any(other_mask):
            ax1.scatter(scores[other_mask, 0], scores[other_mask, 1], color="#c7c7c7", s=10, alpha=0.35, label="Other")
            plotted = True
        if plotted:
            ax1.legend(loc="best", fontsize=8, frameon=True)
        ax1.set_xlabel("PC1")
        ax1.set_ylabel("PC2")
        ax1.grid(True, alpha=0.25)
    else:
        ax1.text(0.5, 0.5, "Not enough PCA components", transform=ax1.transAxes, ha="center", va="center")
    fig.tight_layout()
    fig.savefig(output, dpi=220)
    plt.close(fig)
    return output


def plot_static_presence_drift(
    data: Dict[str, Any],
    out_dir: Path,
    output_filename: str,
    args: argparse.Namespace,
    run_summary: Optional[Dict[str, Any]] = None,
) -> Path:
    plt = get_matplotlib_pyplot()
    features = static_presence_features(np.asarray(data["V_all"]), np.asarray(data["times"]))
    t = features["time_s"]
    t_max = float(np.nanmax(t)) if t.size else 0.0
    x_min, x_max = graph_time_limits(t_max)
    spans, context = experiment_spans_from_record(run_summary, t_max)
    output = out_dir / analysis_filename(output_filename, "static_presence_drift")

    fig, ax = plt.subplots(figsize=(11, 4.2))
    draw_experiment_spans(ax, spans)
    ax.plot(t, moving_average(features["drift"], 5), color="#1f77b4", linewidth=1.6, label="baseline drift")
    ax.plot(t, moving_average(features["correlation_loss"], 5), color="#d62728", linewidth=1.3, label="correlation loss")
    ax.set_xlim(x_min, x_max)
    ax.set_xlabel("Time (s)")
    ax.set_ylabel("Normalized static-presence indicator")
    ax.grid(True, axis="y", alpha=0.25)
    ax.legend(loc="upper right", fontsize=8)
    title = "Static Presence / Baseline Drift"
    if context.get("item"):
        title += f" - Trial {int(context['item_index']) + 1}: {context['item']}"
    ax.set_title(title, fontsize=11)
    fig.tight_layout()
    fig.savefig(output, dpi=220)
    plt.close(fig)
    return output


def save_window_features_csv(
    data: Dict[str, Any],
    out_dir: Path,
    output_filename: str,
    args: argparse.Namespace,
    run_summary: Optional[Dict[str, Any]] = None,
) -> Path:
    V_all = np.asarray(data["V_all"])
    times = np.asarray(data["times"])
    metrics, metric_names, _ = compute_motion_metrics(V_all, data.get("angles_all"), times)
    motion_score, _ = compute_motion_score(metrics, metric_names)
    score_t = metrics[:, 0] if metrics.size else np.zeros((0,), dtype=float)
    static = static_presence_features(V_all, times)
    packet_t = static["time_s"]
    t_max = float(np.nanmax(packet_t)) if packet_t.size else 0.0
    spans, context = experiment_spans_from_record(run_summary, t_max)

    window_seconds = float(getattr(args, "feature_window_seconds", 5.0))
    step_seconds = float(getattr(args, "feature_step_seconds", 1.0))
    output = out_dir / analysis_filename(output_filename, "window_features", ".csv")

    headers = [
        "start_s",
        "end_s",
        "label",
        "kind",
        "record_item",
        "motion_mean",
        "motion_std",
        "motion_p95",
        "motion_max",
        "static_drift_mean",
        "static_corr_loss_mean",
    ]
    with output.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        start = 0.0
        while start < t_max:
            end = min(start + window_seconds, t_max)
            if end <= start:
                break
            motion_mask = (score_t >= start) & (score_t < end)
            static_mask = (packet_t >= start) & (packet_t < end)
            label, kind = label_for_window(start, end, spans)
            motion_values = motion_score[motion_mask] if np.any(motion_mask) else np.asarray([np.nan])
            drift_values = static["drift"][static_mask] if np.any(static_mask) else np.asarray([np.nan])
            corr_values = static["correlation_loss"][static_mask] if np.any(static_mask) else np.asarray([np.nan])
            writer.writerow({
                "start_s": f"{start:.3f}",
                "end_s": f"{end:.3f}",
                "label": label,
                "kind": kind,
                "record_item": context.get("item", ""),
                "motion_mean": f"{float(np.nanmean(motion_values)):.8g}",
                "motion_std": f"{float(np.nanstd(motion_values)):.8g}",
                "motion_p95": f"{float(np.nanpercentile(motion_values, 95)):.8g}",
                "motion_max": f"{float(np.nanmax(motion_values)):.8g}",
                "static_drift_mean": f"{float(np.nanmean(drift_values)):.8g}",
                "static_corr_loss_mean": f"{float(np.nanmean(corr_values)):.8g}",
            })
            start += step_seconds
    return output


def save_extra_analysis_outputs(
    data: Dict[str, Any],
    out_dir: Path,
    args: argparse.Namespace,
    output_filename: str,
    run_summary: Optional[Dict[str, Any]] = None,
) -> Dict[str, str]:
    selected = selected_analysis_names(args)
    outputs: Dict[str, str] = {}
    if "doppler" in selected:
        outputs["doppler_spectrogram"] = str(plot_doppler_spectrogram(data, out_dir, output_filename, args, run_summary))
    if "pca" in selected:
        outputs["csi_ratio_pca"] = str(plot_csi_ratio_pca(data, out_dir, output_filename, args, run_summary))
    if "static" in selected:
        outputs["static_presence_drift"] = str(plot_static_presence_drift(data, out_dir, output_filename, args, run_summary))
    return outputs


def plot_motion_metrics_overview(
    metrics: np.ndarray,
    column_names: List[str],
    out_dir: Path,
    fs_median: float,
    output_filename: str = "motion_metrics_overview.png",
    run_summary: Optional[Dict[str, Any]] = None,
) -> Path:
    plt = get_matplotlib_pyplot()
    if metrics.size == 0 or not column_names:
        raise ValueError("No motion metrics to plot")
    t = metrics[:, 0]
    smooth_window = max(int(round(fs_median * 1.0)), 3) if np.isfinite(fs_median) and fs_median > 0 else 5
    score, score_sources = compute_motion_score(metrics, column_names)
    score = moving_average(score, smooth_window)
    t_max = float(np.nanmax(t)) if t.size else 0.0
    x_min, x_max = graph_time_limits(t_max)
    spans, context = experiment_spans_from_record(run_summary, t_max)

    fig, ax = plt.subplots(figsize=(11, 4.2))
    draw_experiment_spans(ax, spans)
    ax.plot(t, score, color="#111111", linewidth=1.8)
    ax.set_title("BFI Motion Score")
    if context.get("item"):
        ax.set_title(f"BFI Motion Score - Trial {int(context['item_index']) + 1}: {context['item']}", fontsize=11)
    ax.set_xlabel("Time (s)")
    ax.set_ylabel("Normalized motion score")
    ax.grid(True, axis="y", alpha=0.25)
    ax.set_xlim(x_min, x_max)
    if np.any(np.isfinite(score)):
        y_max = max(1.05, float(np.nanpercentile(score, 99)) * 1.15)
        ax.set_ylim(0, y_max)
    source_text = motion_score_source_label(score_sources)
    ax.text(
        0.995,
        0.02,
        f"score: {source_text}",
        transform=ax.transAxes,
        ha="right",
        va="bottom",
        fontsize=7,
        color="#555555",
    )
    fig.tight_layout()
    output = out_dir / output_filename
    fig.savefig(output, dpi=220)
    plt.close(fig)
    return output


def plot_auxiliary_graphs(V_all: np.ndarray, angles_all: np.ndarray, snrs: np.ndarray, times: np.ndarray, out_dir: Path, subcarrier_index: Optional[int]) -> int:
    plt = get_matplotlib_pyplot()
    n_packets, n_sc, nr, nc = V_all.shape
    sc = n_sc // 2 if subcarrier_index is None else int(np.clip(subcarrier_index, 0, n_sc - 1))
    x = times - times[0] if len(times) == n_packets and np.all(np.isfinite(times)) else np.arange(n_packets)
    xlabel = "Time (s)" if len(times) == n_packets and np.all(np.isfinite(times)) else "Packet index"

    plt.figure(figsize=(14, 6))
    for r in range(nr):
        for c in range(nc):
            plt.plot(x, np.unwrap(np.angle(V_all[:, sc, r, c])), linewidth=1.0, label=f"ant{r+1}-ss{c+1}")
    plt.title(f"Subcarrier #{sc}: unwrapped phase of V elements")
    plt.xlabel(xlabel)
    plt.ylabel("Phase (rad)")
    plt.grid(True, alpha=0.4)
    if nr * nc <= 12:
        plt.legend(loc="best", fontsize=8)
    plt.tight_layout()
    plt.savefig(out_dir / f"subcarrier_{sc}_phase.png", dpi=200)
    plt.close()

    plt.figure(figsize=(14, 6))
    for r in range(nr):
        for c in range(nc):
            plt.plot(x, np.abs(V_all[:, sc, r, c]), linewidth=1.0, label=f"ant{r+1}-ss{c+1}")
    plt.title(f"Subcarrier #{sc}: magnitude of V elements")
    plt.xlabel(xlabel)
    plt.ylabel("|V|")
    plt.grid(True, alpha=0.4)
    if nr * nc <= 12:
        plt.legend(loc="best", fontsize=8)
    plt.tight_layout()
    plt.savefig(out_dir / f"subcarrier_{sc}_magnitude.png", dpi=200)
    plt.close()

    if nr >= 2 and nc >= 1:
        rel = V_all[:, sc, 0, 0] * np.conj(V_all[:, sc, 1, 0])
        plt.figure(figsize=(14, 5))
        plt.plot(x, np.unwrap(np.angle(rel)), linewidth=1.0)
        plt.title(f"Subcarrier #{sc}: relative phase ant1 vs ant2, stream1")
        plt.xlabel(xlabel)
        plt.ylabel("Relative phase (rad)")
        plt.grid(True, alpha=0.4)
        plt.tight_layout()
        plt.savefig(out_dir / f"subcarrier_{sc}_relative_phase_ant1_ant2_ss1.png", dpi=200)
        plt.close()

    if angles_all is not None and angles_all.ndim == 3:
        plt.figure(figsize=(14, 6))
        for k in range(angles_all.shape[2]):
            plt.plot(x, angles_all[:, sc, k], linewidth=1.0, label=f"angle{k}")
        plt.title(f"Subcarrier #{sc}: quantized BFI angles")
        plt.xlabel(xlabel)
        plt.ylabel("Quantized angle value")
        plt.grid(True, alpha=0.4)
        plt.legend(loc="best", fontsize=8)
        plt.tight_layout()
        plt.savefig(out_dir / f"subcarrier_{sc}_quantized_angles.png", dpi=200)
        plt.close()

    if snrs is not None and snrs.size:
        snrs2 = np.asarray(snrs, dtype=float)
        if snrs2.ndim == 1:
            snrs2 = snrs2[:, None]
        plt.figure(figsize=(14, 5))
        for c in range(snrs2.shape[1]):
            plt.plot(x, snrs2[:, c], linewidth=1.0, label=f"SNR stream {c+1}")
        plt.title("BFI SNR per stream")
        plt.xlabel(xlabel)
        plt.ylabel("SNR-like value from BFI report")
        plt.grid(True, alpha=0.4)
        plt.legend(loc="best", fontsize=8)
        plt.tight_layout()
        plt.savefig(out_dir / "snr_timeseries.png", dpi=200)
        plt.close()

    return sc


def plot_antenna_health(health_rows: List[Dict[str, Any]], out_dir: Path) -> None:
    plt = get_matplotlib_pyplot()
    if not health_rows:
        return
    labels = [str(r["antenna_index_1based"]) for r in health_rows]
    for key, ylabel, filename in [
        ("mean_power", "Mean row power", "antenna_row_mean_power.png"),
        ("mean_abs_packet_phase_diff", "Mean abs phase diff (rad)", "antenna_row_phase_diff.png"),
        ("mean_abs_packet_complex_diff", "Mean abs complex diff", "antenna_row_complex_diff.png"),
        ("mean_abs_packet_magnitude_diff", "Mean abs magnitude diff", "antenna_row_magnitude_diff.png"),
    ]:
        y = [float(r[key]) for r in health_rows]
        plt.figure(figsize=(9, 5))
        plt.bar(labels, y)
        plt.title(key)
        plt.xlabel("Antenna index")
        plt.ylabel(ylabel)
        plt.grid(True, axis="y", alpha=0.4)
        plt.tight_layout()
        plt.savefig(out_dir / filename, dpi=200)
        plt.close()


def plot_selected_subcarrier_pngs(
    V_all: np.ndarray,
    angles_all: np.ndarray,
    snrs: np.ndarray,
    times: np.ndarray,
    out_dir: Path,
    subcarrier_index: int,
    png_set: str,
) -> int:
    """Save only PNG plots needed for quick analysis. No matrix/CSV/report files."""
    plt = get_matplotlib_pyplot()
    n_packets, n_sc, nr, nc = V_all.shape
    sc = int(np.clip(subcarrier_index, 0, n_sc - 1))
    x = times - times[0] if len(times) == n_packets and np.all(np.isfinite(times)) else np.arange(n_packets)
    xlabel = "Time (s)" if len(times) == n_packets and np.all(np.isfinite(times)) else "Packet index"

    if png_set in {"core", "all"}:
        plt.figure(figsize=(14, 6))
        for r in range(nr):
            for c in range(nc):
                plt.plot(x, np.unwrap(np.angle(V_all[:, sc, r, c])), linewidth=1.0, label=f"ant{r+1}-ss{c+1}")
        plt.title(f"Subcarrier #{sc}: unwrapped phase of BFI matrix V")
        plt.xlabel(xlabel)
        plt.ylabel("Phase (rad)")
        plt.grid(True, alpha=0.4)
        if nr * nc <= 12:
            plt.legend(loc="best", fontsize=8)
        plt.tight_layout()
        plt.savefig(out_dir / f"subcarrier_{sc}_phase.png", dpi=200)
        plt.close()

        plt.figure(figsize=(14, 6))
        for r in range(nr):
            for c in range(nc):
                plt.plot(x, np.abs(V_all[:, sc, r, c]), linewidth=1.0, label=f"ant{r+1}-ss{c+1}")
        plt.title(f"Subcarrier #{sc}: magnitude of BFI matrix V")
        plt.xlabel(xlabel)
        plt.ylabel("|V|")
        plt.grid(True, alpha=0.4)
        if nr * nc <= 12:
            plt.legend(loc="best", fontsize=8)
        plt.tight_layout()
        plt.savefig(out_dir / f"subcarrier_{sc}_magnitude.png", dpi=200)
        plt.close()

        if nr >= 2 and nc >= 1:
            rel = V_all[:, sc, 0, 0] * np.conj(V_all[:, sc, 1, 0])
            plt.figure(figsize=(14, 5))
            plt.plot(x, np.unwrap(np.angle(rel)), linewidth=1.0)
            plt.title(f"Subcarrier #{sc}: relative phase ant1 vs ant2, stream1")
            plt.xlabel(xlabel)
            plt.ylabel("Relative phase (rad)")
            plt.grid(True, alpha=0.4)
            plt.tight_layout()
            plt.savefig(out_dir / f"subcarrier_{sc}_relative_phase_ant1_ant2_ss1.png", dpi=200)
            plt.close()

        if angles_all is not None and angles_all.ndim == 3:
            plt.figure(figsize=(14, 6))
            for k in range(angles_all.shape[2]):
                plt.plot(x, angles_all[:, sc, k], linewidth=1.0, label=f"angle{k}")
            plt.title(f"Subcarrier #{sc}: quantized BFI angles")
            plt.xlabel(xlabel)
            plt.ylabel("Quantized angle value")
            plt.grid(True, alpha=0.4)
            plt.legend(loc="best", fontsize=8)
            plt.tight_layout()
            plt.savefig(out_dir / f"subcarrier_{sc}_quantized_angles.png", dpi=200)
            plt.close()

    if png_set == "all" and snrs is not None and np.asarray(snrs).size:
        snrs2 = np.asarray(snrs, dtype=float)
        if snrs2.ndim == 1:
            snrs2 = snrs2[:, None]
        plt.figure(figsize=(14, 5))
        for c in range(snrs2.shape[1]):
            plt.plot(x, snrs2[:, c], linewidth=1.0, label=f"SNR stream {c+1}")
        plt.title("BFI SNR per stream")
        plt.xlabel(xlabel)
        plt.ylabel("SNR-like value from BFI report")
        plt.grid(True, alpha=0.4)
        plt.legend(loc="best", fontsize=8)
        plt.tight_layout()
        plt.savefig(out_dir / "snr_timeseries.png", dpi=200)
        plt.close()

    return sc


def plot_selected_antenna_pngs(health_rows: List[Dict[str, Any]], out_dir: Path, png_set: str) -> None:
    """Save concise antenna sanity-check PNGs. Phase-only row plots are skipped by default."""
    plt = get_matplotlib_pyplot()
    if not health_rows or png_set not in {"core", "all"}:
        return
    labels = [str(r["antenna_index_1based"]) for r in health_rows]

    wanted = [
        ("mean_power", "Mean row power", "antenna_row_mean_power.png"),
        ("mean_abs_packet_complex_diff", "Mean abs complex diff", "antenna_row_complex_diff.png"),
    ]
    if png_set == "all":
        wanted.extend([
            ("mean_abs_packet_magnitude_diff", "Mean abs magnitude diff", "antenna_row_magnitude_diff.png"),
            ("mean_abs_packet_phase_diff", "Mean abs phase diff (rad)", "antenna_row_phase_diff.png"),
        ])

    for key, ylabel, filename in wanted:
        y = [float(r[key]) for r in health_rows]
        plt.figure(figsize=(9, 5))
        plt.bar(labels, y)
        plt.title(key)
        plt.xlabel("Antenna index")
        plt.ylabel(ylabel)
        plt.grid(True, axis="y", alpha=0.4)
        plt.tight_layout()
        plt.savefig(out_dir / filename, dpi=200)
        plt.close()


def clean_output_png_only(out_dir: Path) -> None:
    """Remove previously generated files in the chosen output directory.

    This is intentionally conservative: it only operates inside --out and is called
    only when --clean-output is explicitly supplied.
    """
    if not out_dir.exists():
        return
    for child in out_dir.iterdir():
        if child.is_file():
            child.unlink()
        elif child.is_dir():
            import shutil
            shutil.rmtree(child)


def save_group_dataset_and_analysis(
    key: BFIGroupKey,
    records: List[BFIPacketRecord],
    out_root: Path,
    args: argparse.Namespace,
    run_summary: Dict[str, Any],
) -> Dict[str, Any]:
    """Stack the selected BFI packets in memory and save the motion graph only."""
    data = stack_records(records)
    return save_stacked_dataset_and_analysis(key, data, out_root, args, run_summary)


def save_stacked_dataset_and_analysis(
    key: BFIGroupKey,
    data: Dict[str, Any],
    out_root: Path,
    args: argparse.Namespace,
    run_summary: Dict[str, Any],
) -> Dict[str, Any]:
    """Save the motion graph from already reconstructed BFI matrix data.

    No .npz, .mat, .csv, .json, or .txt files are written by this function.
    No diagnostic subcarrier, SNR, or antenna PNGs are written.
    """
    out_root.mkdir(parents=True, exist_ok=True)

    V_all = data["V_all"]
    angles_all = data["angles_all"]
    times = data["times"]

    fs_median, fs_count, duration, median_dt, p95_dt, large_gap_count = robust_sampling_rate(times)
    metrics, metric_names, motion_stats = compute_motion_metrics(V_all, angles_all, times)

    output_filename = getattr(args, "motion_png_filename", "motion_metrics_overview.png")
    selected = selected_analysis_names(args)
    overview_png: Optional[Path] = None
    if "motion" in selected:
        overview_png = plot_motion_metrics_overview(
            metrics,
            metric_names,
            out_root,
            fs_median,
            output_filename=output_filename,
            run_summary=run_summary,
        )
    extra_outputs = save_extra_analysis_outputs(data, out_root, args, output_filename, run_summary)

    return {
        "folder": str(out_root),
        "motion_metrics_overview": str(overview_png) if overview_png is not None else None,
        "analysis_outputs": extra_outputs,
        "n_packets": int(V_all.shape[0]),
        "V_shape": list(V_all.shape),
        "group": group_key_to_dict(key),
        "sampling": {
            "fs_median_local_hz": fs_median,
            "fs_count_average_hz": fs_count,
            "duration_s": duration,
            "median_dt_s": median_dt,
            "p95_dt_s": p95_dt,
            "large_gap_count_gt_1s": large_gap_count,
        },
        "motion_stats": motion_stats,
    }


def choose_group(groups: Dict[BFIGroupKey, List[BFIPacketRecord]], args: argparse.Namespace) -> Tuple[BFIGroupKey, List[BFIPacketRecord]]:
    filtered = {k: v for k, v in groups.items() if len(v) >= args.min_packets_per_group}
    if not filtered:
        raise RuntimeError(
            f"No target group has at least {args.min_packets_per_group} packets. "
            "Try lowering --min-packets-per-group or check --source-sta/--ap."
        )
    # User usually wants the main link; choose the largest matching group.
    return max(filtered.items(), key=lambda kv: len(kv[1]))


# -----------------------------------------------------------------------------
# CLI
# -----------------------------------------------------------------------------


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Extract BFI from one PCAP and save only the motion metrics PNG graph."
    )
    parser.add_argument(
        "pcap",
        nargs="?",
        default=None,
        help="Input capture file, capture directory, or BFI intermediate cache directory. If omitted, the newest timestamped capture under --data-dir is used.",
    )
    parser.add_argument("--data-dir", default="data", help="Directory containing timestamped capture files and result folders")
    parser.add_argument("--out", default=None, help="Output directory. Directory input defaults to a new sibling *_motion_png_<timestamp> folder.")
    parser.add_argument("--cache-dir", default=None, help="Directory for parsed BFI intermediate .npz files when reading PCAPs.")
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
    parser.add_argument("--subcarrier-index", type=int, default=139, help=argparse.SUPPRESS)
    parser.add_argument("--png-set", choices=["overview", "core", "all"], default="overview", help=argparse.SUPPRESS)
    parser.add_argument("--clean-output", action="store_true", help="Delete existing contents of --out before writing PNGs")
    parser.add_argument("--force-nr", type=int, default=None, help="Force Nr if auto detection fails")
    parser.add_argument("--force-nc", type=int, default=None, help="Force Nc if auto detection fails")
    parser.add_argument("--force-subcarriers", type=int, default=None, help="Force subcarrier count, e.g., 234 for VHT 80 MHz")
    parser.add_argument("--strict", action="store_true", help="Do not zero-pad incomplete angle payloads")
    parser.add_argument("--min-packets-per-group", type=int, default=20, help="Minimum packets required for analysis")
    parser.add_argument("--max-packets", type=int, default=None, help="Debug: maximum scanned packets")
    parser.add_argument("--progress-every", type=int, default=200, help="Progress print interval")
    parser.add_argument("--phase-zero-tol", type=float, default=1e-12, help=argparse.SUPPRESS)
    parser.add_argument("--verbose", action="store_true", help="Print parse tracebacks")
    return parser


def analyze_capture_to_motion_png(
    pcap_path: Path,
    out_root: Path,
    args: argparse.Namespace,
    output_filename: str,
    cache_path: Optional[Path] = None,
) -> Dict[str, Any]:
    run_args = argparse.Namespace(**vars(args))
    run_args.pcap = str(pcap_path)
    run_args.motion_png_filename = output_filename

    groups, run_summary = extract_bfi_from_pcap(run_args)
    run_summary["output_root"] = str(out_root)
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
    run_summary["groups_after_source_ap_filter"] = [
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

    key, records = choose_group(groups, run_args)
    data = stack_records(records)
    if cache_path is not None:
        saved_cache = save_intermediate_cache(cache_path, data, key, run_summary)
        run_summary["intermediate_cache"] = str(saved_cache)
    result = save_stacked_dataset_and_analysis(key, data, out_root, run_args, run_summary)
    return {"run_summary": run_summary, "result": result}


def analyze_cache_to_motion_png(
    cache_path: Path,
    out_root: Path,
    args: argparse.Namespace,
    output_filename: str,
) -> Dict[str, Any]:
    run_args = argparse.Namespace(**vars(args))
    run_args.motion_png_filename = output_filename
    key, data, run_summary = load_intermediate_cache(cache_path)
    run_summary["output_root"] = str(out_root)
    run_summary["intermediate_cache"] = str(cache_path)
    result = save_stacked_dataset_and_analysis(key, data, out_root, run_args, run_summary)
    return {"run_summary": run_summary, "result": result}


def print_capture_summary(run_summary: Dict[str, Any], result: Dict[str, Any], out_root: Path) -> None:
    print("\n=== BFI PCAP-to-motion complete ===")
    print(f"PCAP:       {run_summary['pcap']}")
    print(f"Output:     {out_root}")
    print(f"Target STA: {run_summary['target_source_sta']}")
    print(f"Target AP:  {run_summary['target_ap']}")
    print(f"Scanned packets:     {run_summary['scanned_packets']}")
    print(f"Parsed BFI packets:  {run_summary['parsed_bfi_packets']}")
    print(f"Kept target packets: {run_summary['kept_target_packets']}")
    print(f"Selected group:      {result['group']}")
    print(f"V_all shape:         {result['V_shape']}")
    if run_summary.get("intermediate_cache"):
        print(f"Intermediate cache:  {run_summary['intermediate_cache']}")
    print(f"Motion graph:        {result['motion_metrics_overview']}")
    print("Saved files:         one motion PNG per PCAP")


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
        try:
            intermediate_paths = [] if capture_paths else find_intermediate_files(input_path)
        except Exception as e:
            print(f"[ERROR] {e}", file=sys.stderr)
            return 2
        if not capture_paths and not intermediate_paths:
            print(f"[ERROR] No PCAP or BFI intermediate files found under: {input_path}", file=sys.stderr)
            return 2

        batch_ts = current_timestamp()
        out_root = Path(args.out).expanduser().resolve() if args.out else default_batch_output_dir(input_path, batch_ts).resolve()
        if args.clean_output:
            clean_output_png_only(out_root)
        out_root.mkdir(parents=True, exist_ok=True)

        successes: List[Dict[str, Any]] = []
        failures: List[Tuple[Path, str]] = []
        used_names: set[str] = set()

        if capture_paths:
            cache_root = (
                Path(args.cache_dir).expanduser().resolve()
                if args.cache_dir
                else default_batch_cache_dir(input_path, batch_ts).resolve()
            )
            cache_root.mkdir(parents=True, exist_ok=True)

            print("\n=== BFI PCAP-to-motion batch ===")
            print(f"Input folder: {input_path}")
            print(f"Output:       {out_root}")
            print(f"Cache:        {cache_root}")
            print(f"PCAP files:   {len(capture_paths)}")

            used_cache_names: set[str] = set()
            for idx, pcap_path in enumerate(capture_paths, start=1):
                output_filename = motion_png_filename_for_capture(pcap_path, input_path, used_names)
                cache_filename = cache_filename_for_capture(pcap_path, input_path, used_cache_names)
                print(f"\n[{idx}/{len(capture_paths)}] Processing: {pcap_path}")
                try:
                    item = analyze_capture_to_motion_png(
                        pcap_path,
                        out_root,
                        args,
                        output_filename,
                        cache_path=cache_root / cache_filename,
                    )
                except Exception as e:
                    failures.append((pcap_path, str(e)))
                    print(f"[ERROR] {pcap_path}: {e}", file=sys.stderr)
                    if getattr(args, "verbose", False):
                        traceback.print_exc()
                    continue

                successes.append(item)
                print(f"Cached: {item['run_summary']['intermediate_cache']}")
                print(f"Saved:  {item['result']['motion_metrics_overview']}")
        else:
            print("\n=== BFI intermediate-to-motion batch ===")
            print(f"Input folder: {input_path}")
            print(f"Output:       {out_root}")
            print(f"Cache files:  {len(intermediate_paths)}")

            for idx, cache_path in enumerate(intermediate_paths, start=1):
                output_filename = motion_png_filename_for_cache(cache_path, input_path, used_names)
                print(f"\n[{idx}/{len(intermediate_paths)}] Loading: {cache_path}")
                try:
                    item = analyze_cache_to_motion_png(cache_path, out_root, args, output_filename)
                except Exception as e:
                    failures.append((cache_path, str(e)))
                    print(f"[ERROR] {cache_path}: {e}", file=sys.stderr)
                    if getattr(args, "verbose", False):
                        traceback.print_exc()
                    continue

                successes.append(item)
                print(f"Saved: {item['result']['motion_metrics_overview']}")

        print("\n=== Batch complete ===")
        print(f"Output:      {out_root}")
        print(f"Succeeded:   {len(successes)}")
        print(f"Failed:      {len(failures)}")
        if failures:
            print("Failed files:")
            for pcap_path, message in failures:
                print(f"  - {pcap_path}: {message}")
        return 2 if not successes else (1 if failures else 0)

    if input_path.is_file() and input_path.name.endswith(INTERMEDIATE_CACHE_SUFFIX):
        cache_path = input_path
        if args.out:
            out_root = Path(args.out).expanduser().resolve()
        else:
            stem = cache_path.name[:-len(INTERMEDIATE_CACHE_SUFFIX)]
            out_root = cache_path.parent / f"{safe_filename_stem(stem)}_motion_png_{current_timestamp()}"

        if args.clean_output:
            clean_output_png_only(out_root)
        out_root.mkdir(parents=True, exist_ok=True)

        try:
            output_filename = motion_png_filename_for_cache(cache_path, None, set())
            item = analyze_cache_to_motion_png(cache_path, out_root, args, output_filename)
        except Exception as e:
            print(f"[ERROR] {e}", file=sys.stderr)
            if getattr(args, "verbose", False):
                traceback.print_exc()
            return 2

        print_capture_summary(item["run_summary"], item["result"], out_root)
        return 0

    pcap_path = input_path

    if args.out:
        out_root = Path(args.out).expanduser().resolve()
    else:
        out_root = default_output_dir_for_capture(pcap_path, data_dir).resolve()
    cache_root = Path(args.cache_dir).expanduser().resolve() if args.cache_dir else default_single_cache_dir(pcap_path, data_dir).resolve()

    if args.clean_output:
        clean_output_png_only(out_root)
    out_root.mkdir(parents=True, exist_ok=True)
    cache_root.mkdir(parents=True, exist_ok=True)

    try:
        cache_filename = cache_filename_for_capture(pcap_path, None, set())
        item = analyze_capture_to_motion_png(
            pcap_path,
            out_root,
            args,
            "motion_metrics_overview.png",
            cache_path=cache_root / cache_filename,
        )

    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        if getattr(args, "verbose", False):
            traceback.print_exc()
        return 2

    print_capture_summary(item["run_summary"], item["result"], out_root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
