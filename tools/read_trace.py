#!/usr/bin/env python3
"""Decode EDGT trace ring buffer from a raw memory dump or live hex input."""

from __future__ import annotations

import argparse
import struct
from pathlib import Path

TRACE_BUF = 0x8C13DE00
MAGIC = 0x54474445
MAX_ENTRIES = 64
ENTRY_SIZE = 16

TAG_NAMES = {
    0x00011650: "fread (FUN_8c011650)",
    0x00014A2E: "load_rlc (FUN_8c014a2e)",
    0x0000AF5C: "menu (FUN_8c06af5c)",
    0x00014708: "attach (FUN_8c014708)",
}


def decode_buf(buf: bytes, base_addr: int = TRACE_BUF) -> list[str]:
    if len(buf) < 16:
        return ["buffer too small"]
    magic, ver, idx = struct.unpack_from("<III", buf, 0)
    lines = [f"magic={magic:#x} ({'EDGT' if magic == MAGIC else '??'}) ver={ver} idx={idx}"]
    if idx > 10_000 or (magic != MAGIC and idx > 256):
        lines.append("(index invalide — buffer probablement jamais écrit par trace_log)")
        return lines
    start = max(0, int(idx) - MAX_ENTRIES)
    for i in range(start, int(idx)):
        off = 16 + (i % MAX_ENTRIES) * ENTRY_SIZE
        if off + ENTRY_SIZE > len(buf):
            break
        tag, a0, a1, a2 = struct.unpack_from("<IIII", buf, off)
        name = TAG_NAMES.get(tag, f"tag={tag:#x}")
        path = ""
        if 0x8C000000 <= a0 < 0x8D000000 and off + 32 <= len(buf):
            raw = buf[off + 16 : off + 32]
            if any(32 <= c < 127 or c in (0x5C,) for c in raw):
                path = raw.split(b"\x00")[0].decode("ascii", "replace")
        lines.append(f"  [{i:3d}] {name}  a0={a0:#x}  a1={a1:#x}  a2={a2:#x}  {path!r}")
    return lines


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--from-file", type=Path, help="Full RAM dump or 4KB slice at TRACE_BUF")
    parser.add_argument("--offset", type=lambda x: int(x, 0), default=0, help="Offset of TRACE_BUF in file")
    parser.add_argument("--hex", type=str, help="Raw hex bytes of 256+ bytes at trace buffer")
    args = parser.parse_args()

    if args.hex:
        buf = bytes.fromhex(args.hex.replace(" ", ""))
    elif args.from_file:
        data = args.from_file.read_bytes()
        buf = data[args.offset : args.offset + 4096]
    else:
        print(__doc__)
        print("\nFlycast: pause le jeu, note les 64 bytes @ 0x8C2FE000, puis:")
        print("  PYTHONPATH=tools python3 tools/read_trace.py --hex '45444754...'")
        return

    for line in decode_buf(buf):
        print(line)


if __name__ == "__main__":
    main()
