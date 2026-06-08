#!/usr/bin/env python3
"""Offline verification of 1ST_READ trace hooks (no emulator)."""

from __future__ import annotations

import struct
import sys
from pathlib import Path

from capstone import Cs, CS_ARCH_SH, CS_MODE_SH4

ROOT = Path(__file__).resolve().parents[1]
LOAD_BASE = 0x8C010000
CODE_CAVE = 0x8C13D800
TRACE_BUF = 0x8C13DE00

HOOKS = {
    "fread": 0x8C011650,
    "load_rlc": 0x8C014A2E,
    "menu": 0x8C06AF5C,
    "attach": 0x8C014708,
}


def read_halfword_le(data: bytes, off: int) -> int:
    return struct.unpack_from("<H", data, off)[0]


def disasm_at(data: bytes, addr: int, size: int) -> list[str]:
    md = Cs(CS_ARCH_SH, CS_MODE_SH4)
    off = addr - LOAD_BASE
    lines = []
    for ins in md.disasm(data[off : off + size], addr):
        lines.append(f"  {ins.address:#x}: {ins.mnemonic} {ins.op_str}")
    return lines


def verify_hook(data: bytes, addr: int, name: str) -> list[str]:
    off = addr - LOAD_BASE
    issues: list[str] = []
    chunk = data[off : off + 16]
    if len(chunk) < 12:
        return [f"{name}: hook offset out of range"]

    md = Cs(CS_ARCH_SH, CS_MODE_SH4)
    insns = list(md.disasm(chunk[:8], addr))
    if len(insns) < 2 or insns[0].mnemonic != "mov.l" or insns[1].mnemonic != "jsr":
        issues.append(f"{name}: expected mov.l/jsr trampoline at {addr:#x}")
        return issues

    lit_addr = int(insns[0].op_str.split(",")[0], 16)
    patch_len = lit_addr - addr
    if patch_len not in (8, 10, 12):
        issues.append(f"{name}: unexpected patch length {patch_len} (literal {lit_addr:#x})")
        patch_len = 8
    stub_ptr = struct.unpack_from("<I", chunk, patch_len)[0]
    if not (CODE_CAVE <= stub_ptr < LOAD_BASE + len(data)):
        issues.append(f"{name}: stub pointer {stub_ptr:#x} outside cave")

    cave_off = stub_ptr - LOAD_BASE
    cave = data[cave_off : cave_off + 0x80]
    if not cave:
        issues.append(f"{name}: empty stub @ {stub_ptr:#x}")
        return issues

    stub_ins = list(md.disasm(cave, stub_ptr))
    if not stub_ins or stub_ins[0].mnemonic != "sts.l":
        issues.append(f"{name}: stub missing sts.l @ {stub_ptr:#x}")
    if not any(i.mnemonic == "jsr" for i in stub_ins[:16]):
        issues.append(f"{name}: stub missing jsr to trace_log")

    return issues


def verify_cave(data: bytes) -> list[str]:
    issues: list[str] = []
    off = CODE_CAVE - LOAD_BASE
    cave = data[off : off + 0x100]
    md = Cs(CS_ARCH_SH, CS_MODE_SH4)
    insns = list(md.disasm(cave, CODE_CAVE))
    if not insns or insns[0].mnemonic != "sts.l":
        issues.append("cave: trace_log must start with sts.l")
    if not any(i.mnemonic == "rts" for i in insns[:40]):
        issues.append("cave: trace_log missing rts")
    # literal TRACE_BUF address near trace_log
    if struct.pack("<I", TRACE_BUF) not in cave:
        issues.append(f"cave: TRACE_BUF literal {TRACE_BUF:#x} not in trace_log")
    return issues


def main() -> int:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "output" / "1ST_READ_trace.bin"
    if not path.exists():
        print(f"Missing {path} — run: PYTHONPATH=tools python3 tools/trace_patch.py")
        return 1

    data = path.read_bytes()
    print(f"=== verify_trace_patch: {path.name} ({len(data)} bytes) ===\n")

    all_ok = True
    for name, addr in HOOKS.items():
        issues = verify_hook(data, addr, name)
        if issues:
            all_ok = False
            print(f"[FAIL] {name} @ {addr:#x}")
            for i in issues:
                print(f"  - {i}")
        else:
            print(f"[OK]   {name} @ {addr:#x}")

    cave_issues = verify_cave(data)
    if cave_issues:
        all_ok = False
        print("[FAIL] code cave")
        for i in cave_issues:
            print(f"  - {i}")
    else:
        print(f"[OK]   code cave @ {CODE_CAVE:#x}")

    print("\n--- trace_log disassembly ---")
    for line in disasm_at(data, CODE_CAVE, 0x40):
        print(line)

    proof = ROOT / "output" / "ghidra_fread_proof.txt"
    if proof.exists():
        print(f"\n[OK]   static proof: {proof}")
    else:
        print(f"\n[WARN] run ghidra_fread_proof.java for static path analysis")

    print(f"\nRAM trace buffer (runtime): {TRACE_BUF:#x}")
    print("Sans debugger: Flycast → Save State (F5) → tools/flycast_state_scan.py <fichier.state>")
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
