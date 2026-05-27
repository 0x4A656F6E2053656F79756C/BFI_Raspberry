#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bfi_pcap_to_motion_png_only.py

One-file pipeline:
  PCAP/PCAPNG -> Wi-Fi 5/6 compressed BFI extraction -> source/AP filtering
  -> BFI V matrix reconstruction -> motion metrics -> PNG plots only

Default target link:
  source STA = 2c:cf:67:17:0a:3c
  AP         = 08:bf:b8:95:80:04

Install:
  pip install pyshark numpy matplotlib
  # Also install Wireshark/TShark and make sure `tshark` is on PATH.

Examples:
  python bfi_pcap_to_motion_png_only.py

  python bfi_pcap_to_motion_png_only.py test_13.pcap

  python bfi_pcap_to_motion_png_only.py test_13.pcap --out bfi_motion_png \
      --source-sta 2c:cf:67:17:0a:3c --ap 08:bf:b8:95:80:04

  python bfi_pcap_to_motion_png_only.py test_13.pcap --out bfi_motion_png \
      --source-sta bc:45:5b:d3:b9:70 --ap 60:38:e0:bb:ee:02

Notes:
- This script intentionally defaults to pyshark normal mode, not EK mode, because some
  Windows TShark builds do not support elastic-mapping.
- For HE/Wi-Fi 6 raw fallback, try --capture-mode json and adjust --he-raw-offset-bytes.
"""

from __future__ import annotations

import argparse
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

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
except Exception as exc:  # pragma: no cover
    raise RuntimeError("matplotlib is required. Install with: pip install matplotlib") from exc



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

    candidates = [
        p for p in data_dir.rglob("*")
        if p.is_file() and p.suffix.lower() in CAPTURE_EXTENSIONS
    ]
    if not candidates:
        raise FileNotFoundError(f"No capture files found under: {data_dir}")

    def sort_key(path: Path) -> Tuple[int, str, float, str]:
        ts = timestamp_from_path(path)
        stat = path.stat()
        return (1 if ts else 0, ts or "", stat.st_mtime, str(path))

    return max(candidates, key=sort_key)


def default_output_dir_for_capture(pcap_path: Path, data_dir: Path) -> Path:
    ts = timestamp_from_path(pcap_path) or current_timestamp()
    return data_dir.expanduser().resolve() / f"{ts}_result"


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
    }


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


def plot_motion_metrics_overview(metrics: np.ndarray, column_names: List[str], out_dir: Path, fs_median: float) -> Path:
    if metrics.size == 0 or not column_names:
        raise ValueError("No motion metrics to plot")
    t = metrics[:, 0]
    smooth_window = max(int(round(fs_median * 1.0)), 3) if np.isfinite(fs_median) and fs_median > 0 else 5

    plt.figure(figsize=(14, 6))
    for idx, name in enumerate(column_names[1:], start=1):
        y = metrics[:, idx]
        scale = np.nanpercentile(np.abs(y), 95)
        y_plot = y / scale if np.isfinite(scale) and scale > 0 else y
        plt.plot(t, moving_average(y_plot, smooth_window), linewidth=1.0, label=name)
    plt.title("Normalized motion metrics overview")
    plt.xlabel("Time (s)")
    plt.ylabel("Normalized value, p95 scale")
    plt.grid(True, alpha=0.4)
    plt.legend(loc="best", fontsize=8)
    plt.tight_layout()
    output = out_dir / "motion_metrics_overview.png"
    plt.savefig(output, dpi=200)
    plt.close()
    return output


def plot_auxiliary_graphs(V_all: np.ndarray, angles_all: np.ndarray, snrs: np.ndarray, times: np.ndarray, out_dir: Path, subcarrier_index: Optional[int]) -> int:
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
    """Stack the selected BFI packets in memory and save PNG graphs only.

    No .npz, .mat, .csv, .json, or .txt files are written by this function.
    """
    out_root.mkdir(parents=True, exist_ok=True)

    data = stack_records(records)
    V_all = data["V_all"]
    angles_all = data["angles_all"]
    snrs = data["snrs"]
    times = data["times"]

    fs_median, fs_count, duration, median_dt, p95_dt, large_gap_count = robust_sampling_rate(times)
    health_rows, health_summary = antenna_diagnostics(V_all, phase_zero_tol=args.phase_zero_tol)
    metrics, metric_names, motion_stats = compute_motion_metrics(V_all, angles_all, times)

    overview_png = plot_motion_metrics_overview(metrics, metric_names, out_root, fs_median)
    selected_sc = plot_selected_subcarrier_pngs(
        V_all=V_all,
        angles_all=angles_all,
        snrs=snrs,
        times=times,
        out_dir=out_root,
        subcarrier_index=args.subcarrier_index,
        png_set=args.png_set,
    )
    plot_selected_antenna_pngs(health_rows, out_root, args.png_set)

    return {
        "folder": str(out_root),
        "motion_metrics_overview": str(overview_png),
        "selected_subcarrier": int(selected_sc),
        "n_packets": int(len(records)),
        "V_shape": list(V_all.shape),
        "antenna_overall_status": health_summary.get("overall_status"),
        "group": {
            "source": key.source_hex12,
            "source_colon": mac_colon(key.source_hex12),
            "ap": key.ap_hex12,
            "ap_colon": mac_colon(key.ap_hex12),
            "protocol": key.protocol,
            "nr": key.nr,
            "nc": key.nc,
            "n_subcarriers": key.n_subcarriers,
            "bw": key.bw,
            "grouping": key.grouping,
        },
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
        description="Extract BFI from one PCAP and save only PNG analysis plots."
    )
    parser.add_argument(
        "pcap",
        nargs="?",
        default=None,
        help="Input .pcap/.pcapng/.wcap file. If omitted, the newest timestamped capture under --data-dir is used.",
    )
    parser.add_argument("--data-dir", default="data", help="Directory containing timestamped capture files and result folders")
    parser.add_argument("--out", default=None, help="Output directory; default is data/<capture_timestamp>_result")
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
    parser.add_argument("--subcarrier-index", type=int, default=139, help="Example subcarrier index; default is 139")
    parser.add_argument("--png-set", choices=["overview", "core", "all"], default="core", help="PNG outputs: overview=only motion_metrics_overview.png; core=overview + subcarrier 139 + antenna sanity PNGs; all=also SNR/phase-only diagnostics")
    parser.add_argument("--clean-output", action="store_true", help="Delete existing contents of --out before writing PNGs")
    parser.add_argument("--force-nr", type=int, default=None, help="Force Nr if auto detection fails")
    parser.add_argument("--force-nc", type=int, default=None, help="Force Nc if auto detection fails")
    parser.add_argument("--force-subcarriers", type=int, default=None, help="Force subcarrier count, e.g., 234 for VHT 80 MHz")
    parser.add_argument("--strict", action="store_true", help="Do not zero-pad incomplete angle payloads")
    parser.add_argument("--min-packets-per-group", type=int, default=20, help="Minimum packets required for analysis")
    parser.add_argument("--max-packets", type=int, default=None, help="Debug: maximum scanned packets")
    parser.add_argument("--progress-every", type=int, default=200, help="Progress print interval")
    parser.add_argument("--phase-zero-tol", type=float, default=1e-12, help="Tolerance for reference-real phase detection")
    parser.add_argument("--verbose", action="store_true", help="Print parse tracebacks")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    data_dir = Path(args.data_dir).expanduser().resolve()
    if args.pcap:
        pcap_path = Path(args.pcap).expanduser().resolve()
    else:
        pcap_path = find_latest_capture(data_dir)
    args.pcap = str(pcap_path)

    if args.out:
        out_root = Path(args.out).expanduser().resolve()
    else:
        out_root = default_output_dir_for_capture(pcap_path, data_dir).resolve()

    if args.clean_output:
        clean_output_png_only(out_root)
    out_root.mkdir(parents=True, exist_ok=True)

    try:
        groups, run_summary = extract_bfi_from_pcap(args)
        run_summary["output_root"] = str(out_root)
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

        key, records = choose_group(groups, args)
        result = save_group_dataset_and_analysis(key, records, out_root, args, run_summary)

    except Exception as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        if getattr(args, "verbose", False):
            traceback.print_exc()
        return 2

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
    print(f"Antenna status:      {result['antenna_overall_status']}")
    print(f"Selected subcarrier: {result['selected_subcarrier']}")
    print(f"Main graph:          {result['motion_metrics_overview']}")
    print("Saved files:         PNG only")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
