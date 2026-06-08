"""SH-4 instruction bytes for Dreamcast hooks (little-endian halfwords)."""

from __future__ import annotations

import struct


def _h(w: int) -> bytes:
    return struct.pack("<H", w & 0xFFFF)


def nop() -> bytes:
    return _h(0x0009)


def rts() -> bytes:
    return _h(0x000B)


def sts_pr_dec(rn: int = 15) -> bytes:
    if rn == 15:
        return _h(0x4F22)
    raise NotImplementedError(rn)


def lds_pr_inc(rn: int = 15) -> bytes:
    if rn == 15:
        return _h(0x4F26)
    raise NotImplementedError(rn)


def movl_rn_dec(rm: int, rn: int = 15) -> bytes:
    """mov.l Rm,@-Rn"""
    table = {
        (4, 15): 0x2F46,
        (5, 15): 0x2F56,
        (6, 15): 0x2F66,
        (7, 15): 0x2F76,
    }
    key = (rm, rn)
    if key not in table:
        raise NotImplementedError(f"movl_rn_dec r{rm},@-r{rn}")
    return _h(table[key])


def movl_rn_inc(rm: int, rn: int = 15) -> bytes:
    """mov.l @Rn+,Rm"""
    table = {
        (4, 15): 0x64F6,
        (5, 15): 0x65F6,
        (6, 15): 0x66F6,
        (7, 15): 0x67F6,
    }
    key = (rm, rn)
    if key not in table:
        raise NotImplementedError(f"movl_rn_inc @r{rn}+,r{rm}")
    return _h(table[key])


def movl_rn_disp(rm: int, disp: int, rn: int) -> bytes:
    """mov.l Rm,@(disp,Rn)"""
    table = {
        (1, 8, 0): 0x1012,
        (4, 0, 3): 0x1340,
        (5, 4, 3): 0x1351,
        (6, 8, 3): 0x1362,
        (7, 12, 3): 0x1373,
    }
    key = (rm, disp, rn)
    if key not in table:
        raise NotImplementedError(f"movl_rn_disp r{rm},@({disp},r{rn})")
    return _h(table[key])


def movl_disp_rn(disp: int, rm: int, rn: int) -> bytes:
    """mov.l @(disp,Rm),Rn"""
    table = {
        (8, 0, 1): 0x5102,
        (0, 15, 5): 0x55F0,
        (4, 15, 6): 0x56F1,
        (8, 15, 5): 0x55F2,
        (8, 15, 6): 0x56F2,
        (12, 15, 4): 0x54F3,
        (12, 15, 5): 0x55F3,
        (0, 15, 7): 0x57F0,
    }
    key = (disp, rm, rn)
    if key not in table:
        raise NotImplementedError(f"movl_disp_rn @({disp},r{rm}),r{rn}")
    return _h(table[key])


def movl_pc_at(insn_addr: int, rn: int, target_addr: int) -> bytes:
    """mov.l @(disp,PC),Rn — encode via capstone search (PC-rel layout is fiddly)."""
    from capstone import Cs, CS_ARCH_SH, CS_MODE_SH4

    md = Cs(CS_ARCH_SH, CS_MODE_SH4)
    suffix = f",r{rn}"
    for w in range(0x10000):
        ins = list(md.disasm(struct.pack("<H", w), insn_addr))
        if not ins:
            continue
        i = ins[0]
        if i.mnemonic != "mov.l" or not i.op_str.endswith(suffix):
            continue
        label = i.op_str.split(",")[0].strip()
        if label.startswith("0x"):
            if int(label, 16) == target_addr:
                return _h(w)
    raise NotImplementedError(
        f"movl_pc_at insn={insn_addr:#x} r{rn} -> {target_addr:#x}"
    )


def movl_pc(rn: int, disp_words: int) -> bytes:
    """Placeholder halfword; patch with movl_pc_at before emitting."""
    return _h(0x0009)


def mov_rn_rm(rm: int, rn: int) -> bytes:
    """mov Rm,Rn"""
    table = {
        (0, 3): 0x6303,
        (1, 2): 0x6213,
        (4, 5): 0x6543,
        (13, 5): 0x65D3,
        (11, 6): 0x66B3,
    }
    key = (rm, rn)
    if key not in table:
        raise NotImplementedError(f"mov r{rm},r{rn}")
    return _h(table[key])


def mov_imm(imm: int, rn: int) -> bytes:
    val = 0xE000 | (rn << 8) | (imm & 0xFF)
    return _h(val)


def add_imm(imm: int, rn: int) -> bytes:
    val = 0x7000 | (rn << 8) | (imm & 0xFF)
    return _h(val)


def add_rm_rn(rm: int, rn: int) -> bytes:
    """add Rm,Rn"""
    table = {
        (2, 3): 0x332C,
    }
    key = (rm, rn)
    if key not in table:
        raise NotImplementedError(f"add r{rm},r{rn}")
    return _h(table[key])


def shll2(rn: int) -> bytes:
    table = {1: 0x4108, 2: 0x4208}
    if rn not in table:
        raise NotImplementedError(f"shll2 r{rn}")
    return _h(table[rn])


def jsr(rm: int) -> bytes:
    table = {1: 0x410B}
    if rm not in table:
        raise NotImplementedError(f"jsr @r{rm}")
    return _h(table[rm])


def jmp(rm: int) -> bytes:
    table = {0: 0x402B}
    if rm not in table:
        raise NotImplementedError(f"jmp @r{rm}")
    return _h(table[rm])


def hook_jump(cave_addr: int, insn_addr: int, patch_len: int | None = None) -> bytes:
    if patch_len is None:
        patch_len = 8
        while (insn_addr + patch_len) % 4 != 0:
            patch_len += 2
    literal_pc = insn_addr + patch_len
    code = bytearray()
    code += movl_pc_at(insn_addr, 1, literal_pc)
    code += jsr(1)
    while len(code) < patch_len:
        code += nop()
    assert len(code) == patch_len
    return bytes(code) + struct.pack("<I", cave_addr & 0xFFFFFFFF)


def verify_with_capstone(code: bytes, addr: int, limit: int | None = None) -> None:
    try:
        from capstone import Cs, CS_ARCH_SH, CS_MODE_SH4

        md = Cs(CS_ARCH_SH, CS_MODE_SH4)
        chunk = code if limit is None else code[:limit]
        for ins in md.disasm(chunk, addr):
            print(f"  {ins.address:#x}: {ins.mnemonic} {ins.op_str}")
    except ImportError:
        pass
