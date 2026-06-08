#!/usr/bin/env python3
"""
El Dorado Gate Vol.1 — RLC text decoder (work in progress).

Reverse-engineering summary (1ST_READ.BIN @ 0x8C010000, Ghidra 12):

The .RLC files are NOT LZ-compressed on disc. FUN_8c011650 reads them verbatim from
the GD-ROM filesystem. The "compression" is a script bytecode + glyph-index encoding
expanded at runtime.

Call chain (dialogue):
  FUN_8c01a0c4        — scene script loader (references f00_XX.rlc table @ 0x8C0AD10C)
  FUN_8c018f48        — text mode dispatch (param=1 single-byte, 2 dual-tile, else 8-byte tiles)
  FUN_8c019000        — init text VM context @ DAT_8c019074
  FUN_8c01902c        — VM step dispatcher
    [0] FUN_8c01907c  — resolve script slot / refcount
    [1] FUN_8c0190f6  — open RLC stream (FUN_8c011650) + attach buffer
    [2] FUN_8c0191be  — parse segment table into runtime nodes
  FUN_8c018fca        — glyph lookup helper → FUN_8c01927a

Filesystem (no text decompression):
  FUN_8c011650 → FUN_8c012b3a / FUN_8c012c10 — path normalize + ISO read

RLC container:
  u32 segment_count
  [u32 offset, u32 meta] * count
  segment[0] often starts with 0x80 0x00 0x01 0x10 (header/config)
  segment[n>=1] starts with u32 command id (2,4,6,7,...) + bytecode payload
"""

from __future__ import annotations

import argparse
import csv
import struct
from dataclasses import dataclass
from pathlib import Path

# Known from FUN_8c018f48 decompilation
CMD_NAMES = {
    2: "short_event",
    4: "branch",
    6: "dialogue",
    7: "dialogue_alt",
    0x17: "unknown_17",
    0x26: "unknown_26",
    0x36: "unknown_36",
    0x43: "unknown_43",
    0x4F: "unknown_4f",
}


@dataclass
class Segment:
    index: int
    offset: int
    meta: int
    payload: bytes


def parse_rlc(data: bytes) -> list[Segment]:
    if len(data) < 4:
        return []
    count = struct.unpack_from("<I", data, 0)[0]
    if count > 10_000 or 4 + count * 8 > len(data):
        return []
    offsets: list[tuple[int, int]] = []
    for i in range(count):
        off = struct.unpack_from("<I", data, 4 + i * 8)[0]
        meta = struct.unpack_from("<I", data, 8 + i * 8)[0]
        offsets.append((off, meta))
    segments: list[Segment] = []
    for i, (off, meta) in enumerate(offsets):
        if off >= len(data):
            continue
        end = offsets[i + 1][0] if i + 1 < count else len(data)
        if end <= off:
            end = len(data)
        segments.append(Segment(i, off, meta, data[off:end]))
    return segments


def decode_header_segment(payload: bytes) -> list[str]:
    """Parse 0x80-prefixed config segment (enemy name table, script setup)."""
    notes: list[str] = []
    if len(payload) < 4 or payload[0] != 0x80:
        return notes
    notes.append(f"header_magic={payload[:5].hex()}")
    # EN_OBJ pattern: after 80 00 01 10 XX 00 00 comes u16 count then glyph tuples
    if len(payload) >= 8 and payload[1:4] == b"\x00\x01\x10":
        notes.append(f"subtype_byte=0x{payload[4]:02x}")
    return notes


def extract_glyph_runs(payload: bytes) -> list[str]:
    """
    Heuristic: pull likely SJIS glyph pairs and ASCII from command payload.
    Full decode requires the font tables in DPFONT/*.DAT (FUN_8c018f48 indices).
    """
    runs: list[str] = []
    i = 0
    while i < len(payload):
        if payload[i] == 0x1F:
            i += 1
            continue
        if payload[i] == 0x80:
            i += 1
            continue
        if 0x20 <= payload[i] < 0x7F:
            start = i
            while i < len(payload) and 0x20 <= payload[i] < 0x7F:
                i += 1
            runs.append(payload[start:i].decode("ascii"))
            continue
        if (0x81 <= payload[i] <= 0x9F or 0xE0 <= payload[i] <= 0xFC) and i + 1 < len(payload):
            b2 = payload[i + 1]
            if 0x40 <= b2 <= 0xFC:
                try:
                    ch = payload[i : i + 2].decode("shift_jis")
                    if "\u3040" <= ch <= "\u9fff":
                        runs.append(ch)
                except UnicodeDecodeError:
                    pass
                i += 2
                continue
        i += 1
    return runs


def decode_segment(seg: Segment) -> dict:
    payload = seg.payload
    if not payload:
        return {"kind": "empty", "notes": [], "text_parts": []}

    if payload[0] == 0x80:
        return {
            "kind": "header",
            "notes": decode_header_segment(payload),
            "text_parts": extract_glyph_runs(payload[5:]),
        }

    if len(payload) >= 4:
        cmd = struct.unpack_from("<I", payload, 0)[0]
        body = payload[4:]
        return {
            "kind": CMD_NAMES.get(cmd, f"cmd_{cmd}"),
            "cmd_id": cmd,
            "notes": [f"body_len={len(body)}", f"body_head={body[:16].hex()}"],
            "text_parts": extract_glyph_runs(body),
        }

    return {"kind": "raw", "notes": [], "text_parts": extract_glyph_runs(payload)}


def decode_file(path: Path) -> list[dict]:
    data = path.read_bytes()
    rows: list[dict] = []
    for seg in parse_rlc(data):
        decoded = decode_segment(seg)
        text = "".join(decoded["text_parts"])
        rows.append(
            {
                "source_file": str(path),
                "segment_index": seg.index,
                "segment_offset": f"0x{seg.offset:X}",
                "segment_size": len(seg.payload),
                "meta": f"0x{seg.meta:X}",
                "kind": decoded["kind"],
                "cmd_id": decoded.get("cmd_id", ""),
                "notes": "; ".join(decoded["notes"]),
                "text_guess": text,
                "translation_en": "",
            }
        )
    return rows


def export_csv(rows: list[dict], out_csv: Path) -> None:
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "source_file",
        "segment_index",
        "segment_offset",
        "segment_size",
        "meta",
        "kind",
        "cmd_id",
        "notes",
        "text_guess",
        "translation_en",
    ]
    with out_csv.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="RLC file or directory")
    parser.add_argument("-o", "--csv", type=Path, default=Path("output/rlc_decoded.csv"))
    args = parser.parse_args()

    paths = sorted(args.input.rglob("*.RLC")) if args.input.is_dir() else [args.input]
    rows: list[dict] = []
    for path in paths:
        rows.extend(decode_file(path))

    export_csv(rows, args.csv)
    dialogue = sum(1 for r in rows if r["kind"] in ("dialogue", "dialogue_alt"))
    print(f"Decoded {len(rows)} segments from {len(paths)} files ({dialogue} dialogue) -> {args.csv}")


if __name__ == "__main__":
    main()
