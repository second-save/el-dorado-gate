#!/usr/bin/env python3
"""Patch a file inside a Dreamcast padded ISO or track03.bin by ISO9660 extent."""

from __future__ import annotations

import argparse
import struct
from pathlib import Path

LBA_OFFSET = 45000
SECTOR_RAW = 2352
SECTOR_HEADER = 16
SECTOR_DATA = 2048


def read_extent_padded(iso: bytes, extent: int, size: int) -> bytes:
    data = bytearray()
    lba = extent
    while len(data) < size:
        off = lba * SECTOR_DATA
        data.extend(iso[off : off + SECTOR_DATA])
        lba += 1
    return bytes(data[:size])


def write_extent_padded(iso: bytearray, extent: int, payload: bytes) -> None:
    lba = extent
    pos = 0
    while pos < len(payload):
        off = lba * SECTOR_DATA
        chunk = payload[pos : pos + SECTOR_DATA]
        iso[off : off + len(chunk)] = chunk
        pos += len(chunk)
        lba += 1


def read_extent_track3(track3: bytes, extent: int, size: int) -> bytes:
    data = bytearray()
    lba = extent
    while len(data) < size:
        sector_idx = lba - LBA_OFFSET
        sector = track3[sector_idx * SECTOR_RAW : (sector_idx + 1) * SECTOR_RAW]
        data.extend(sector[SECTOR_HEADER : SECTOR_HEADER + SECTOR_DATA])
        lba += 1
    return bytes(data[:size])


def write_extent_track3(track3: bytearray, extent: int, payload: bytes) -> None:
    lba = extent
    pos = 0
    while pos < len(payload):
        sector_idx = lba - LBA_OFFSET
        sector_off = sector_idx * SECTOR_RAW
        chunk = payload[pos : pos + SECTOR_DATA]
        start = sector_off + SECTOR_HEADER
        track3[start : start + len(chunk)] = chunk
        pos += len(chunk)
        lba += 1


def find_extent(iso: bytes, filename: str, root_extent: int = 45020, root_size: int = 2048) -> tuple[int, int]:
    """Return (extent, size) for a case-insensitive ISO9660 file name."""

    def parse_dir(lba: int, size: int) -> list[tuple[str, int, int, bool]]:
        data = read_extent_padded(iso, lba, size)
        entries: list[tuple[str, int, int, bool]] = []
        pos = 0
        while pos < size:
            rec_len = data[pos]
            if rec_len == 0:
                pos = ((pos // SECTOR_DATA) + 1) * SECTOR_DATA
                if pos >= size:
                    break
                continue
            extent = struct.unpack_from("<I", data, pos + 2)[0]
            data_len = struct.unpack_from("<I", data, pos + 10)[0]
            flags = data[pos + 25]
            name_len = data[pos + 32]
            name = data[pos + 33 : pos + 33 + name_len].decode("ascii", errors="replace")
            name = name.split(";")[0]
            entries.append((name, extent, data_len, bool(flags & 2)))
            pos += rec_len
        return entries

    def walk(lba: int, size: int, prefix: str) -> tuple[int, int] | None:
        for name, extent, data_len, is_dir in parse_dir(lba, size):
            if name in ("", ".", "\x00", "\x01"):
                continue
            full = f"{prefix}/{name}" if prefix else name
            if not is_dir and name.upper() == filename.upper():
                return extent, data_len
            if is_dir:
                hit = walk(extent, data_len, full)
                if hit:
                    return hit
        return None

    hit = walk(root_extent, root_size, "")
    if hit is None:
        raise FileNotFoundError(f"{filename} not found in ISO9660 tree")
    return hit


def patch_file_at_extent(
    *,
    iso_path: Path | None,
    track3_path: Path | None,
    extent: int,
    payload: bytes,
    out_iso: Path | None,
    out_track3: Path | None,
) -> None:
    if iso_path:
        iso = bytearray(iso_path.read_bytes())
        write_extent_padded(iso, extent, payload)
        target = out_iso or iso_path
        target.write_bytes(iso)
        print(f"ISO  patched -> {target} @ LBA {extent} ({hex(extent * SECTOR_DATA)})")

    if track3_path:
        track3 = bytearray(track3_path.read_bytes())
        write_extent_track3(track3, extent, payload)
        target = out_track3 or track3_path
        target.write_bytes(track3)
        print(f"track03 patched -> {target} @ LBA {extent}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iso", type=Path, help="Padded ISO (eldorado_padded.iso)")
    parser.add_argument("--track3", type=Path, help="GDI track03.bin")
    parser.add_argument("--file", type=Path, help="Replacement file bytes")
    parser.add_argument("--name", help="ISO9660 filename to locate (e.g. SELOBJ.RLC)")
    parser.add_argument("--extent", type=int, help="Explicit LBA extent (overrides --name)")
    parser.add_argument("--out-iso", type=Path)
    parser.add_argument("--out-track3", type=Path)
    args = parser.parse_args()

    if not args.iso and not args.track3:
        raise SystemExit("Provide --iso and/or --track3")
    if not args.file:
        raise SystemExit("Provide --file")

    payload = args.file.read_bytes()
    if args.extent is not None:
        extent = args.extent
    elif args.name and args.iso:
        extent, size = find_extent(args.iso.read_bytes(), args.name)
        if len(payload) > size:
            raise SystemExit(f"Payload {len(payload)} exceeds directory size {size}")
        if len(payload) < size:
            payload = payload + b"\x00" * (size - len(payload))
    else:
        raise SystemExit("Provide --extent or (--iso and --name)")

    patch_file_at_extent(
        iso_path=args.iso,
        track3_path=args.track3,
        extent=extent,
        payload=payload,
        out_iso=args.out_iso,
        out_track3=args.out_track3,
    )


if __name__ == "__main__":
    main()
