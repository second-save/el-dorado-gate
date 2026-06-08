#!/usr/bin/env python3
"""Parse El Dorado Gate .RLC script containers and export text blobs to CSV."""

from __future__ import annotations

import argparse
import csv
import re
import struct
from dataclasses import dataclass
from pathlib import Path


@dataclass
class RlcSegment:
    index: int
    offset: int
    meta: int
    size: int
    payload: bytes


@dataclass
class TextCandidate:
    source_file: str
    segment_index: int
    blob_offset: int
    blob_hex: str
    sjis_guess: str
    note: str


def parse_rlc(data: bytes) -> list[RlcSegment]:
    if len(data) < 4:
        return []
    count = struct.unpack_from("<I", data, 0)[0]
    header_end = 4 + count * 8
    if header_end > len(data) or count > 10_000:
        return []

    segments: list[RlcSegment] = []
    for i in range(count):
        offset = struct.unpack_from("<I", data, 4 + i * 8)[0]
        meta = struct.unpack_from("<I", data, 8 + i * 8)[0]
        if offset >= len(data):
            continue
        next_offset = (
            struct.unpack_from("<I", data, 4 + (i + 1) * 8)[0]
            if i + 1 < count
            else len(data)
        )
        end = min(next_offset, len(data)) if next_offset > offset else len(data)
        payload = data[offset:end]
        segments.append(RlcSegment(i, offset, meta, len(payload), payload))
    return segments


def extract_text_blobs(segment: bytes) -> list[tuple[int, bytes]]:
    """Heuristic: find runs that look like encoded dialogue (0x80.. opcodes + SJIS-like bytes)."""
    blobs: list[tuple[int, bytes]] = []
    i = 0
    while i < len(segment):
        if segment[i] == 0x80 and i + 2 < len(segment):
            start = i
            i += 1
            while i < len(segment) and segment[i] != 0x80:
                i += 1
            chunk = segment[start:i]
            if len(chunk) >= 8:
                blobs.append((start, chunk))
            continue
        i += 1
    return blobs


def sjis_guess(blob: bytes) -> tuple[str, str]:
    """Best-effort decode. Returns (text, note)."""
    # Plain Shift-JIS
    try:
        text = blob.decode("shift_jis")
        if any("\u3040" <= c <= "\u9fff" for c in text):
            return text, "plain_sjis"
    except UnicodeDecodeError:
        pass

    # Strip 0x80 control tokens and retry
    stripped = bytes(b for b in blob if b not in (0x80, 0x00, 0xFF))
    try:
        text = stripped.decode("shift_jis", errors="replace")
        if any("\u3040" <= c <= "\u9fff" for c in text):
            return text, "sjis_after_strip_controls"
    except UnicodeDecodeError:
        pass

    # Visible ASCII fallback
    ascii_parts = re.findall(rb"[\x20-\x7e]{4,}", blob)
    if ascii_parts:
        return ascii_parts[0].decode("ascii"), "ascii_only"

    return "", "compressed_or_unknown"


def scan_rlc_file(path: Path) -> list[TextCandidate]:
    data = path.read_bytes()
    segments = parse_rlc(data)
    results: list[TextCandidate] = []

    for seg in segments:
        for blob_offset, blob in extract_text_blobs(seg.payload):
            guess, note = sjis_guess(blob)
            if not guess and len(blob) < 12:
                continue
            results.append(
                TextCandidate(
                    source_file=str(path),
                    segment_index=seg.index,
                    blob_offset=seg.offset + blob_offset,
                    blob_hex=blob[:120].hex(),
                    sjis_guess=guess[:500],
                    note=note,
                )
            )
    return results


def export_csv(rows: list[TextCandidate], out_csv: Path) -> None:
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(
            [
                "source_file",
                "segment_index",
                "blob_offset",
                "encoding_note",
                "text_guess",
                "blob_hex_preview",
                "translation_en",
            ]
        )
        for row in rows:
            writer.writerow(
                [
                    row.source_file,
                    row.segment_index,
                    f"0x{row.blob_offset:X}",
                    row.note,
                    row.sjis_guess,
                    row.blob_hex,
                    "",
                ]
            )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="RLC file or directory")
    parser.add_argument("-o", "--csv", type=Path, default=Path("output/text_candidates.csv"))
    args = parser.parse_args()

    paths: list[Path]
    if args.input.is_dir():
        paths = sorted(args.input.rglob("*.RLC")) + sorted(args.input.rglob("*.rlc"))
    else:
        paths = [args.input]

    rows: list[TextCandidate] = []
    for path in paths:
        rows.extend(scan_rlc_file(path))

    export_csv(rows, args.csv)
    print(f"Wrote {len(rows)} candidates to {args.csv}")


if __name__ == "__main__":
    main()
