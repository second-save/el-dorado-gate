#!/usr/bin/env python3
"""
Inject trace hooks into 1ST_READ.BIN (load @ 0x8C010000).

Hooks:
  0x8C011650  fread / segment reader  (path in R4)
  0x8C014A2E  RLC full-file load      (path in R5)
  0x8C06AF5C  menu cursor handler     (state ptr R13)
  0x8C014708  segment attach          (seg R5, slot R4)

RAM ring buffer @ 0x8C13DE000 (après code cave) — lire dans Flycast (pause → memory @ cette adresse):
  +0x00  'EDGT'  +0x04 ver=1  +0x08 index
  +0x10  64 entries x 16 bytes: tag, arg0, arg1, arg2

  PYTHONPATH=tools python3 tools/trace_patch.py
  PYTHONPATH=tools python3 tools/read_trace.py --hex '...'
"""

from __future__ import annotations

import argparse
import shutil
import struct
from pathlib import Path

from sh4_asm import (
    add_imm,
    add_rm_rn,
    hook_jump,
    jmp,
    jsr,
    lds_pr_inc,
    mov_imm,
    mov_rn_rm,
    movl_disp_rn,
    movl_pc,
    movl_pc_at,
    movl_rn_dec,
    movl_rn_disp,
    movl_rn_inc,
    nop,
    rts,
    shll2,
    sts_pr_dec,
    verify_with_capstone,
)

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_1ST = ROOT / "disc_extracted" / "1ST_READ.BIN"
DEFAULT_GDI = ROOT / "[GDI] Eldorado Gate - Volume 1 (Japan)" / "Eldorado Gate - Volume 1 (Japan)"
LOAD_BASE = 0x8C010000
CODE_CAVE = 0x8C13D800
TRACE_BUF = CODE_CAVE + 0x600  # colocalisé avec la cave (zone chargée depuis 1ST_READ)
FIRST_READ_EXTENT = 548384

HOOKS = {
    "fread": (0x8C011650, 0x8C011658, bytes.fromhex("521ff364611ff366")),
    "load_rlc": (0x8C014A2E, 0x8C014A38, bytes.fromhex("224ff07f6360511f")),
    "menu": (0x8C06AF5C, 0x8C06AF64, bytes.fromhex("c62fb62fa62f224f")),
    "attach": (0x8C014708, 0x8C014710, bytes.fromhex("a62f224ffc7f0ad3")),
}

TAG = {
    "fread": 0x00011650,
    "load_rlc": 0x00014A2E,
    "menu": 0x0000AF5C,
    "attach": 0x00014708,
}


def _patch_movl_pc(
    code: bytearray, insn_off: int, rn: int, lit_abs: int, insn_base: int
) -> None:
    insn_addr = insn_base + insn_off
    code[insn_off : insn_off + 2] = movl_pc_at(insn_addr, rn, lit_abs)


def build_trace_log() -> bytes:
    """trace_log(r4=tag, r5=a0, r6=a1, r7=a2)."""
    code = bytearray()
    code += sts_pr_dec()
    for r in (4, 5, 6, 7):
        code += movl_rn_dec(r)

    mov_buf_i = len(code)
    code += movl_pc(0, 0)

    code += movl_disp_rn(8, 0, 1)
    code += add_imm(1, 1)
    code += movl_rn_disp(1, 8, 0)
    code += mov_rn_rm(1, 2)
    code += shll2(2)
    code += shll2(2)
    code += mov_rn_rm(0, 3)
    code += add_imm(16, 3)
    code += add_rm_rn(2, 3)

    code += movl_disp_rn(12, 15, 4)
    code += movl_rn_disp(4, 0, 3)
    code += movl_disp_rn(8, 15, 5)
    code += movl_rn_disp(5, 4, 3)
    code += movl_disp_rn(4, 15, 6)
    code += movl_rn_disp(6, 8, 3)
    code += movl_disp_rn(0, 15, 7)
    code += movl_rn_disp(7, 12, 3)

    for r in (7, 6, 5, 4):
        code += movl_rn_inc(r)
    code += lds_pr_inc()
    code += rts()
    while len(code) % 4 != 0:
        code += nop()

    lit_pos = len(code)
    code += struct.pack("<I", TRACE_BUF)
    _patch_movl_pc(code, mov_buf_i, 0, CODE_CAVE + lit_pos, CODE_CAVE)
    return bytes(code)


def build_hook_stub(
    stub_base: int,
    tag: int,
    resume: int,
    stolen: bytes,
    log_addr: int,
    arg_setup: bytes,
) -> bytes:
    code = bytearray()
    code += sts_pr_dec()
    code += movl_rn_dec(4)

    mov_tag_i = len(code)
    code += movl_pc(4, 0)
    code += arg_setup

    mov_log_i = len(code)
    code += movl_pc(1, 0)
    code += jsr(1)
    code += nop()

    stolen8 = stolen[:8]
    if len(stolen8) < 8:
        stolen8 += b"\x09\x00" * ((8 - len(stolen8)) // 2)
    code += stolen8

    mov_res_i = len(code)
    code += movl_pc(0, 0)
    code += jmp(0)
    code += nop()
    while len(code) % 4 != 0:
        code += nop()

    tag_lit = len(code)
    code += struct.pack("<III", tag, resume, log_addr)

    _patch_movl_pc(code, mov_tag_i, 4, stub_base + tag_lit, stub_base)
    _patch_movl_pc(code, mov_log_i, 1, stub_base + tag_lit + 8, stub_base)
    _patch_movl_pc(code, mov_res_i, 0, stub_base + tag_lit + 4, stub_base)

    return bytes(code)


def arg_fread() -> bytes:
    return mov_rn_rm(4, 5) + mov_imm(0, 6) + mov_imm(0, 7)


def arg_load() -> bytes:
    return mov_imm(0, 7)


def arg_menu() -> bytes:
    return mov_rn_rm(13, 5) + mov_imm(0, 6) + mov_imm(0, 7)


def arg_attach() -> bytes:
    return mov_rn_rm(11, 6) + mov_imm(0, 7)


ARG_SETUP = {
    "fread": arg_fread,
    "load_rlc": arg_load,
    "menu": arg_menu,
    "attach": arg_attach,
}


def build_cave() -> tuple[bytes, dict[str, int]]:
    cave = bytearray(0x600)
    off = 0

    log = build_trace_log()
    cave[off : off + len(log)] = log
    log_addr = CODE_CAVE + off
    off = (off + len(log) + 3) & ~3

    stubs: dict[str, int] = {}
    for name, (_fn, resume, stolen) in HOOKS.items():
        stub = build_hook_stub(
            CODE_CAVE + off,
            TAG[name],
            resume,
            stolen,
            log_addr,
            ARG_SETUP[name](),
        )
        cave[off : off + len(stub)] = stub
        stubs[name] = CODE_CAVE + off
        off = (off + len(stub) + 3) & ~3

    return bytes(cave), stubs


def patch_1st_read(data: bytearray) -> dict[str, int]:
    cave, stubs = build_cave()
    off = CODE_CAVE - LOAD_BASE
    if off + len(cave) > len(data):
        raise SystemExit(f"cave overflow: need {off + len(cave)}, have {len(data)}")
    data[off : off + len(cave)] = cave
    buf_off = TRACE_BUF - LOAD_BASE
    data[buf_off : buf_off + 12] = struct.pack("<III", 0x54474445, 1, 0)

    patched = {}
    for name, (fn, _resume, _stolen) in HOOKS.items():
        poff = fn - LOAD_BASE
        patch = hook_jump(stubs[name], fn)
        data[poff : poff + len(patch)] = patch
        patched[name] = fn
    return patched


def patch_gdi(gdi_dir: Path, patched: bytes, out_dir: Path, label: str) -> Path:
    import iso_patch as ip
    from selobj_patch import patch_track1_ip_title, rename_gdi_descriptor

    out_dir.mkdir(parents=True, exist_ok=True)
    for name in ("track01.bin", "track02.raw", "track03.bin"):
        src = gdi_dir / name
        if src.exists():
            shutil.copy2(src, out_dir / name)
    template = gdi_dir / "Eldorado Gate Vol. 1 v1.002 (2000)(Capcom)(JP)[!].gdi"
    shutil.copy2(template, out_dir / template.name)

    track3 = bytearray((out_dir / "track03.bin").read_bytes())
    ip.write_extent_track3(track3, FIRST_READ_EXTENT, patched)
    (out_dir / "track03.bin").write_bytes(track3)

    n = patch_track1_ip_title(out_dir / "track01.bin", label)
    gdi_path = rename_gdi_descriptor(out_dir, label)
    print(f"IP.BIN titles patched: {n}")
    return gdi_path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--1st-read", dest="first_read", type=Path, default=DEFAULT_1ST)
    parser.add_argument("--out-1st", type=Path, default=ROOT / "output" / "1ST_READ_trace.bin")
    parser.add_argument("--gdi-dir", type=Path, default=DEFAULT_GDI)
    parser.add_argument("--gdi-out", type=Path, default=ROOT / "output" / "gdi_trace_test")
    parser.add_argument("--no-gdi", action="store_true")
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()

    if args.verify_only:
        cave, stubs = build_cave()
        print(f"cave {len(cave)} bytes, log @ {CODE_CAVE:#x}")
        print("--- trace_log ---")
        log_len = build_trace_log().__len__()
        verify_with_capstone(cave[:log_len], CODE_CAVE)
        for k, v in stubs.items():
            print(f"stub {k} @ {v:#x}")
            stub_off = v - CODE_CAVE
            verify_with_capstone(cave[stub_off : stub_off + 0x40], v)
        return

    data = bytearray(args.first_read.read_bytes())
    hooks = patch_1st_read(data)
    args.out_1st.parent.mkdir(parents=True, exist_ok=True)
    args.out_1st.write_bytes(data)
    print(f"Wrote {args.out_1st}")
    print("Hooks:", {k: f"{v:#x}" for k, v in hooks.items()})
    print(f"Lire le buffer @ {TRACE_BUF:#x} dans Flycast après avoir navigué le menu")

    if not args.no_gdi:
        gdi = patch_gdi(args.gdi_dir, bytes(data), args.gdi_out, "trace-log")
        print(f"GDI: {gdi}")


if __name__ == "__main__":
    main()
