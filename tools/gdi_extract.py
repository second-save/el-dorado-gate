#!/usr/bin/env python3
"""Extract files from a Dreamcast GDI dump (El Dorado Gate Vol. 1)."""

from __future__ import annotations

import argparse
import struct
from dataclasses import dataclass
from pathlib import Path


LBA_OFFSET = 45000
SECTOR_RAW = 2352
SECTOR_HEADER = 16
SECTOR_DATA = 2048
ROOT_EXTENT = 45020
ROOT_SIZE = 2048


@dataclass
class DiscEntry:
    name: str
    extent: int
    size: int
    is_dir: bool


def build_padded_iso(track3: Path, out_iso: Path | None = None) -> bytes:
    raw = track3.read_bytes()
    chunks = [b"\x00" * (LBA_OFFSET * SECTOR_DATA)]
    for i in range(len(raw) // SECTOR_RAW):
        sector = raw[i * SECTOR_RAW : (i + 1) * SECTOR_RAW]
        chunks.append(sector[SECTOR_HEADER : SECTOR_HEADER + SECTOR_DATA])
    iso = b"".join(chunks)
    if out_iso:
        out_iso.write_bytes(iso)
    return iso


def read_sectors(iso: bytes, lba: int, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        data.extend(iso[lba * SECTOR_DATA : (lba + 1) * SECTOR_DATA])
        lba += 1
    return bytes(data[:size])


def parse_directory(iso: bytes, lba: int, size: int) -> list[DiscEntry]:
    data = read_sectors(iso, lba, size)
    entries: list[DiscEntry] = []
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
        entries.append(DiscEntry(name, extent, data_len, bool(flags & 2)))
        pos += rec_len
    return entries


def walk_tree(iso: bytes, path: str, lba: int, size: int) -> list[DiscEntry]:
    found: list[DiscEntry] = []
    for entry in parse_directory(iso, lba, size):
        if entry.name in ("", ".", "\x00", "\x01"):
            continue
        full = f"{path}/{entry.name}" if path else entry.name
        if entry.is_dir:
            found.extend(walk_tree(iso, full, entry.extent, entry.size))
        else:
            found.append(DiscEntry(full, entry.extent, entry.size, False))
    return found


def extract_all(iso: bytes, out_dir: Path, pattern: str | None = None) -> list[DiscEntry]:
    out_dir.mkdir(parents=True, exist_ok=True)
    files = walk_tree(iso, "", ROOT_EXTENT, ROOT_SIZE)
    extracted: list[DiscEntry] = []
    for entry in files:
        if pattern and pattern.lower() not in entry.name.lower():
            continue
        payload = read_sectors(iso, entry.extent, entry.size)
        target = out_dir / entry.name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
        extracted.append(entry)
    return extracted


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("gdi_dir", type=Path, help="Directory containing track03.bin")
    parser.add_argument("-o", "--out", type=Path, default=Path("disc_extracted"))
    parser.add_argument("--iso", type=Path, help="Also write padded ISO image")
    parser.add_argument("--pattern", help="Only extract paths containing this substring")
    args = parser.parse_args()

    track3 = args.gdi_dir / "track03.bin"
    if not track3.exists():
        raise SystemExit(f"Missing track03.bin in {args.gdi_dir}")

    iso = build_padded_iso(track3, args.iso)
    files = extract_all(iso, args.out, args.pattern)
    print(f"Extracted {len(files)} files to {args.out}")


if __name__ == "__main__":
    main()
