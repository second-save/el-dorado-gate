#!/usr/bin/env python3
"""Static fread/selobj proof from ROM + existing Ghidra dumps (no emulator)."""

from __future__ import annotations

import re
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "disc_extracted" / "1ST_READ.BIN"
OUT = ROOT / "output" / "static_fread_proof.txt"

LOAD = 0x8C010000
FILE_TABLE = 0x8C0B0828
FREAD_PTR = 0x8C014B1C
FREAD = 0x8C011650


def read_cstr(data: bytes, va: int, limit: int = 64) -> str:
    off = va - LOAD
    end = data.find(b"\x00", off, off + limit)
    if end < 0:
        end = off + limit
    return data[off:end].decode("ascii", "replace")


def main() -> None:
    data = BIN.read_bytes()
    lines: list[str] = []
    lines.append("STATIC FREAD / SELOBJ PROOF (no emulator)")
    lines.append("")

    lines.append("=== File table @0x8C0B0828 ===")
    for i in range(4):
        off = FILE_TABLE - LOAD + i * 8
        path_va, meta = struct.unpack_from("<II", data, off)
        path = read_cstr(data, path_va)
        lines.append(f"  [{i}] {path!r} meta={meta:#x}")

    fread_ptr = struct.unpack_from("<I", data, FREAD_PTR - LOAD)[0]
    lines.append("")
    lines.append(f"PTR_8c014b1c -> fread = {fread_ptr:#x} (expect {FREAD:#x})")
    lines.append("")

    lines.append("=== selobj.rlc string xrefs in ROM ===")
    needle = b"selobj.rlc"
    pos = 0
    while True:
        hit = data.find(needle, pos)
        if hit < 0:
            break
        va = LOAD + hit
        lines.append(f"  string @ {va:#x}")
        pos = hit + 1

    lines.append("")
    lines.append("=== Ghidra cross-refs (cached) ===")
    for name in ("ghidra_textbox_trace.txt", "ghidra_menu.txt", "ghidra_menu_init.txt"):
        p = ROOT / "output" / name
        if not p.exists():
            continue
        text = p.read_text(errors="replace")
        if "8c011650" in text or "PTR_FUN_8c014b1c" in text:
            lines.append(f"  {name}: references fread loader chain")
        m = re.search(r"PTR_8c014b1c.*", text)
        if m:
            lines.append(f"    {m.group(0).strip()}")

    lines.append("")
    lines.append("=== Runtime tests without debugger ===")
    lines.append("  1. Nuclear GDI (SELOBJ=0xFF): menu unchanged => disk SELOBJ not sole source")
    lines.append("  2. Trace GDI: hooks verified offline via verify_trace_patch.py")
    lines.append("  3. Flycast Save State (F5) -> flycast_state_scan.py <file.state>")
    lines.append("")
    lines.append("=== Expected trace tags (if hooks fire) ===")
    lines.append("  fread    0x00011650  path ptr in a0")
    lines.append("  load_rlc 0x00014A2E  path ptr in a0")
    lines.append("  menu     0x0000AF5C  state ptr in a0")
    lines.append("  attach   0x00014708  segment in a0")

    OUT.write_text("\n".join(lines) + "\n")
    print(OUT.read_text())


if __name__ == "__main__":
    main()
