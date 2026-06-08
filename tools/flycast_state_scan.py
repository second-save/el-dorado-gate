#!/usr/bin/env python3
"""
Extract trace buffer from a Flycast save state (no memory debugger needed).

Flycast: jouer avec le GDI trace-log, naviguer le menu, F5 (Save State),
puis passer le fichier .state (souvent dans savestates/ à côté du .gdi).

Usage:
  PYTHONPATH=tools python3 tools/flycast_state_scan.py ~/path/to/game.state
  PYTHONPATH=tools python3 tools/flycast_state_scan.py --raw ~/path/to/blob.bin
"""

from __future__ import annotations

import argparse
import struct
import zlib
from pathlib import Path

from read_trace import TAG_NAMES, TRACE_BUF, decode_buf, ENTRY_SIZE, MAX_ENTRIES
MAIN_RAM_BASE = 0x8C000000
MAIN_RAM_SIZE = 16 * 1024 * 1024
LOAD_BASE = 0x8C010000
CODE_CAVE = 0x8C13D800
MAGIC = 0x54474445  # EDGT

TAG_BYTES = {
    0x00011650: "fread",
    0x00014A2E: "load_rlc",
    0x0000AF5C: "menu",
    0x00014708: "attach",
}

ROOT = Path(__file__).resolve().parents[1]
REF_1ST = ROOT / "output" / "1ST_READ_trace.bin"


def _hook_signatures() -> tuple[bytes, bytes]:
    """(fread trampoline, load_rlc trampoline) from patched 1ST_READ."""
    if REF_1ST.exists():
        ref = REF_1ST.read_bytes()
        return (
            ref[0x8C011650 - LOAD_BASE : 0x8C011650 - LOAD_BASE + 8],
            ref[0x8C014A2E - LOAD_BASE : 0x8C014A2E - LOAD_BASE + 8],
        )
    return (bytes.fromhex("70d200400c326484"), bytes.fromhex("02d10b4109000900"))


def decompress_flysave1(data: bytes) -> bytes:
    """Decompress Flycast .state (FLYSAVE1 + optional PNG + #RZI chunks)."""
    if data[:8] == b"FLYSAVE1":
        png_size = struct.unpack_from("<I", data, 20)[0]
        pos = 24 + png_size
        if pos + 20 > len(data) or data[pos : pos + 4] != b"#RZI":
            raise ValueError("FLYSAVE1 without #RZI payload")
        # #RZI + u32 flags + u32 max_chunk + u32 total
        total = struct.unpack_from("<I", data, pos + 12)[0]
        pos += 20
        out = bytearray()
        while len(out) < total and pos + 4 <= len(data):
            zsize = struct.unpack_from("<I", data, pos)[0]
            pos += 4
            if zsize == 0:
                break
            out.extend(zlib.decompress(data[pos : pos + zsize]))
            pos += zsize
        return bytes(out[:total])

    if data[:4] == b"PK\x03\x04":
        import io
        import zipfile

        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            name = max(zf.namelist(), key=lambda n: zf.getinfo(n).file_size)
            return zf.read(name)
    if data[:2] in (b"\x1f\x8b", b"\x78\x9c", b"\x78\xda"):
        return zlib.decompress(data)
    return data


def decompress_state_blob(data: bytes) -> bytes:
    try:
        return decompress_flysave1(data)
    except (ValueError, zlib.error):
        return data


def _ram_slice_ok(blob: bytes, ram_base: int, ram_off: int, size: int) -> bool:
    start = ram_base + ram_off
    return ram_base >= 0 and start >= 0 and start + size <= len(blob)


def find_main_ram(blob: bytes) -> int | None:
    """Locate 1ST_READ load base inside serialized state (anchor @ 0x8C010000)."""
    fread_sig, load_sig = _hook_signatures()
    load_off = 0x8C011650 - LOAD_BASE
    load_patch_off = 0x8C014A2E - LOAD_BASE
    trace_off = TRACE_BUF - LOAD_BASE
    cave_off = CODE_CAVE - LOAD_BASE
    need = max(trace_off + 16 + MAX_ENTRIES * ENTRY_SIZE, cave_off + 0x100)
    pos = 0
    while pos < len(blob):
        hit = blob.find(fread_sig, pos)
        if hit < 0:
            return None
        ram_base = hit - load_off
        if _ram_slice_ok(blob, ram_base, load_patch_off, 8):
            if blob[ram_base + load_patch_off : ram_base + load_patch_off + 8] == load_sig:
                if _ram_slice_ok(blob, ram_base, need - 1, 1):
                    return ram_base
        pos = hit + 1
    return None


def read_c_string(ram: bytes, ram_base: int, addr: int, max_len: int = 64) -> str:
    if not (LOAD_BASE <= addr < LOAD_BASE + MAIN_RAM_SIZE):
        return ""
    off = ram_base + (addr - LOAD_BASE)
    if off < 0 or off >= len(ram):
        return ""
    raw = ram[off : off + max_len]
    if not raw:
        return ""
    z = raw.split(b"\x00")[0]
    if not z or not all(32 <= c < 127 or c == 0x5C for c in z):
        return ""
    return z.decode("ascii", errors="replace")


def is_ring_entry(tag: int, a0: int, a1: int, a2: int) -> bool:
    """Reject literal pools in the code cave (tag + resume PC + log ptr)."""
    if tag not in TAG_BYTES:
        return False
    resume = {
        0x00011650: 0x8C011658,
        0x00014A2E: 0x8C014A38,
        0x0000AF5C: 0x8C06AF64,
        0x00014708: 0x8C014710,
    }[tag]
    if a0 == resume and CODE_CAVE <= a1 < CODE_CAVE + 0x800:
        return False
    return True


def scan_trace_slots(ram: bytes, ram_base: int) -> list[str]:
    trace_off = TRACE_BUF - LOAD_BASE
    if ram_base + trace_off + 16 + MAX_ENTRIES * ENTRY_SIZE > len(ram):
        return ["trace buffer offset out of serialized RAM"]

    chunk = ram[ram_base + trace_off : ram_base + trace_off + 16 + MAX_ENTRIES * ENTRY_SIZE]
    lines = list(decode_buf(chunk, TRACE_BUF))

    ring_hits = 0
    for slot in range(MAX_ENTRIES):
        eoff = 16 + slot * ENTRY_SIZE
        tag, a0, a1, a2 = struct.unpack_from("<IIII", chunk, eoff)
        if not is_ring_entry(tag, a0, a1, a2):
            continue
        ring_hits += 1
        name = TAG_BYTES[tag]
        path = read_c_string(ram, ram_base, a0)
        extra = f"  path={path!r}" if path else ""
        lines.append(f"  ** slot {slot}: {name} a0={a0:#x} a1={a1:#x} a2={a2:#x}{extra}")

    if ring_hits == 0:
        lines.append("")
        lines.append(f"Aucune entrée trace valide dans le ring buffer @ {TRACE_BUF:#x}.")
        lines.append("(Les tags trouvés ailleurs sont les literal pools des stubs @ 0x8C13D800.)")

    return lines


def scan_blob(data: bytes) -> list[str]:
    lines: list[str] = []
    blob = decompress_state_blob(data)
    lines.append(f"decompressed size: {len(blob)} bytes")

    ram_base = find_main_ram(blob)
    if ram_base is not None:
        lines.append(f"main RAM @ blob offset {ram_base:#x}")
        cave = blob[ram_base + (CODE_CAVE - LOAD_BASE) : ram_base + (CODE_CAVE - LOAD_BASE) + 16]
        if cave[:2] == bytes.fromhex("224f"):  # sts.l pr,@-r15
            lines.append(f"code cave present in RAM @ {CODE_CAVE:#x}")
        else:
            lines.append(f"code cave @ {CODE_CAVE:#x}: absent or not loaded ({cave[:8].hex()})")
        lines.extend(scan_trace_slots(blob, ram_base))
        return lines

    # fallback: naive offset (often wrong on compressed wrapper)
    off = TRACE_BUF - MAIN_RAM_BASE
    if off + 0x400 <= len(blob):
        chunk = blob[off : off + 16 + MAX_ENTRIES * ENTRY_SIZE]
        idx = struct.unpack_from("<I", chunk, 8)[0]
        if 0 < idx < 10_000 and struct.unpack_from("<I", chunk, 0)[0] == MAGIC:
            lines.append(f"trace @ blob offset {off:#x} (no RAM anchor)")
            lines.extend(decode_buf(chunk, TRACE_BUF))
            return lines

    hits = []
    for tag, name in TAG_BYTES.items():
        count = blob.count(struct.pack("<I", tag))
        if count:
            hits.append(f"  tag {name}: {count} occurrence(s) in blob")
    lines.append("No main RAM anchor found (patched fread hook missing?).")
    if hits:
        lines.append("Raw tag hits (includes code-cave literal pools):")
        lines.extend(hits)
    else:
        lines.append("No hook tags — confirm trace GDI is loaded and menu was reached.")
    return lines


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("state", type=Path, nargs="?", help="Flycast .state file")
    parser.add_argument("--raw", type=Path, help="Raw decompressed blob")
    args = parser.parse_args()

    if args.raw:
        data = args.raw.read_bytes()
    elif args.state:
        data = args.state.read_bytes()
    else:
        parser.print_help()
        print("\nFlycast macOS: ~/Library/Application Support/Flycast/savestates/")
        print("Ou glisser le .state depuis le dossier du GDI.")
        return

    for line in scan_blob(data):
        print(line)


if __name__ == "__main__":
    main()
