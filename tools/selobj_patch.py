#!/usr/bin/env python3
"""
Patch COMN/SELOBJ.RLC main-menu description text.

Ghidra chain:
  FUN_8c06b3a4  — reads ushort routing pairs in SELOBJ segment 0
  FUN_8c014708  — attaches RLC segment N from selobj.rlc
  FUN_8c014cd0  — renders description text box

Routing (seg 0 pairs N,N):
  NEW GAME    -> segment 1 (cmd 16, inline glyph stream)
  CONTINUE    -> segment 2 (cmd 16)
  HOME PAGE   -> segment 3 (cmd 7)
  OPTION      -> segment 4 (cmd 7)
  MEMORY CARD -> segment 5 (cmd 7)
"""

from __future__ import annotations

import argparse
import shutil
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SELOBJ = ROOT / "disc_extracted" / "COMN" / "SELOBJ.RLC"
DEFAULT_ISO = ROOT / "eldorado_padded.iso"
DEFAULT_GDI_DIR = ROOT / "[GDI] Eldorado Gate - Volume 1 (Japan)" / "Eldorado Gate - Volume 1 (Japan)"
SELOBJ_EXTENT = 442735

MENU_SEGMENTS: dict[str, int] = {
    "NEW GAME": 1,
    "CONTINUE": 2,
    "HOME PAGE": 3,
    "OPTION": 4,
    "MEMORY CARD": 5,
}

NEW_GAME_JP = (
    "ロードせずに新たにゲームをはじめます。\n"
    "これまでに集めたアイテムや装備品が\n"
    "あっても、ゲーム内には反映されません。"
)

NEW_GAME_EN = "New Game"

DEFAULT_GDI_DESCRIPTOR = "Eldorado Gate Vol. 1 v1.002 (2000)(Capcom)(JP)[!].gdi"
IP_TITLE_ORIG = b"ELDORADO GATE VOL1"
IP_TITLE_LEN = 16


def gdi_descriptor_for_label(label: str) -> str:
    safe = label.strip().replace("/", "-")
    return f"Eldorado Gate Vol.1 [TEST {safe}].gdi"


def ip_title_for_label(label: str) -> bytes:
    """16-byte Dreamcast disc title shown in emulators (IP.BIN)."""
    short = {
        "swap-continue": "EDG TEST SWAP",
        "new-game-en": "EDG TEST NEWGAME",
        "proof": "EDG TEST PROOF",
        "nuclear": "EDG TEST NUKLR",
        "menu-legacy": "EDG TEST LEGACY",
    }.get(label, f"EDG TEST {label[:6].upper()}")
    title = short.encode("ascii")
    if len(title) > IP_TITLE_LEN:
        title = title[:IP_TITLE_LEN]
    return title + b" " * (IP_TITLE_LEN - len(title))


def patch_track1_ip_title(track1: Path, label: str) -> int:
    """Stamp every IP.BIN copy in track01 so Flycast shows which GDI is loaded."""
    data = bytearray(track1.read_bytes())
    title = ip_title_for_label(label)
    count = 0
    start = 0
    while True:
        pos = data.find(IP_TITLE_ORIG, start)
        if pos < 0:
            break
        data[pos : pos + IP_TITLE_LEN] = title
        count += 1
        start = pos + IP_TITLE_LEN
    track1.write_bytes(data)
    return count


def rename_gdi_descriptor(gdi_out: Path, label: str) -> Path:
    """Rename the copied TOSEC .gdi so each test build is obvious in Flycast."""
    target = gdi_out / gdi_descriptor_for_label(label)
    if target.exists():
        target.unlink()
    for path in sorted(gdi_out.glob("*.gdi")):
        path.rename(target)
        return target
    raise FileNotFoundError(f"No .gdi descriptor found in {gdi_out}")


def parse_rlc(data: bytes) -> list[tuple[int, int, int, bytes]]:
    count = struct.unpack_from("<I", data, 0)[0]
    rows: list[tuple[int, int, int, bytes]] = []
    offsets: list[tuple[int, int]] = []
    for i in range(count):
        off = struct.unpack_from("<I", data, 4 + i * 8)[0]
        meta = struct.unpack_from("<I", data, 8 + i * 8)[0]
        offsets.append((off, meta))
    for i, (off, meta) in enumerate(offsets):
        end = offsets[i + 1][0] if i + 1 < count else len(data)
        rows.append((i, off, meta, data[off:end]))
    return rows


def patch_copy_body(data: bytearray, dst_index: int, src_index: int) -> None:
    """Copy src segment body into dst segment body (prefix), same RLC file."""
    segments = {s[0]: s for s in parse_rlc(data)}
    dst = segments[dst_index]
    src = segments[src_index]
    payload = bytearray(dst[3])
    src_payload = src[3]
    if len(src_payload) < 4 or len(payload) < 4:
        raise ValueError("Segment payload too small")
    body = bytearray(payload[4:])
    src_body = src_payload[4:]
    if len(src_body) > len(body):
        raise ValueError(
            f"Source segment {src_index} body ({len(src_body)} B) "
            f"larger than dest segment {dst_index} body ({len(body)} B)"
        )
    copy_len = min(len(src_body), len(body))
    body[:copy_len] = src_body[:copy_len]
    if copy_len < len(body):
        body[copy_len:] = bytes(len(body) - copy_len)
    payload[4:] = body
    data[dst[1] : dst[1] + len(payload)] = payload


def patch_new_game_glyph(data: bytearray) -> tuple[int, int]:
    """Subtle test in NEW GAME segment 1: flip a distinctive body byte."""
    segments = {s[0]: s for s in parse_rlc(data)}
    seg = segments[MENU_SEGMENTS["NEW GAME"]]
    payload = bytearray(seg[3])
    body = bytearray(payload[4:])
    # After layout header, first text-ish marker area in seg1
    rel = body.find(b"\xba\x21")
    if rel < 0:
        rel = body.find(bytes.fromhex("03bbff2f")) + 8
    body[rel] ^= 0xFF
    payload[4:] = body
    data[seg[1] : seg[1] + len(payload)] = payload
    return seg[1] + 4 + rel, 1


def patch_nuclear_selobj(data: bytearray) -> None:
    """Fill entire SELOBJ with 0xFF — menu should break if this file is actually read."""
    for i in range(len(data)):
        data[i] = 0xFF


def write_iso_and_track3(
    rlc_path: Path,
    *,
    iso_in: Path,
    iso_out: Path,
    gdi_dir: Path | None,
    gdi_out: Path | None,
    gdi_label: str | None,
    mirror_hack_offset: int | None,
) -> None:
    iso_patch = ROOT / "tools" / "iso_patch.py"
    payload = rlc_path.read_bytes()
    if iso_in.exists():
        subprocess.run(
            [
                sys.executable,
                str(iso_patch),
                "--iso",
                str(iso_in),
                "--file",
                str(rlc_path),
                "--extent",
                str(SELOBJ_EXTENT),
                "--out-iso",
                str(iso_out),
            ],
            check=True,
        )
        if mirror_hack_offset is not None:
            iso = bytearray(iso_out.read_bytes())
            end = mirror_hack_offset + len(payload)
            if end <= len(iso):
                iso[mirror_hack_offset : mirror_hack_offset + len(payload)] = payload
                iso_out.write_bytes(iso)

    if gdi_dir and gdi_dir.exists() and gdi_out:
        if gdi_out.exists():
            shutil.rmtree(gdi_out)
        shutil.copytree(gdi_dir, gdi_out)
        subprocess.run(
            [
                sys.executable,
                str(iso_patch),
                "--track3",
                str(gdi_out / "track03.bin"),
                "--file",
                str(rlc_path),
                "--extent",
                str(SELOBJ_EXTENT),
            ],
            check=True,
        )
        if gdi_label:
            n = patch_track1_ip_title(gdi_out / "track01.bin", gdi_label)
            print(f"  IP.BIN title -> {ip_title_for_label(gdi_label).decode().strip()!r} ({n} copies)")
        gdi_path = (
            rename_gdi_descriptor(gdi_out, gdi_label)
            if gdi_label
            else gdi_out / DEFAULT_GDI_DESCRIPTOR
        )
        print(f"GDI test -> {gdi_out}")
        print(f"  Ouvrir: {gdi_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selobj", type=Path, default=DEFAULT_SELOBJ)
    parser.add_argument(
        "--swap-continue",
        action="store_true",
        help="NEW GAME (seg 1) shows CONTINUE text (copy seg 2 -> seg 1)",
    )
    parser.add_argument("--proof", action="store_true", help="Flip one bytecode byte in NEW GAME seg 1")
    parser.add_argument(
        "--nuclear",
        action="store_true",
        help="Fill SELOBJ with 0xFF (diagnostic: proves whether this file is read)",
    )
    parser.add_argument(
        "--new-game-en",
        nargs="?",
        const=NEW_GAME_EN,
        default=None,
        metavar="TEXT",
        help=f'Replace NEW GAME description with English (default: "{NEW_GAME_EN}")',
    )
    parser.add_argument("--show-text", action="store_true", help="Print JP + EN + routing table")
    parser.add_argument("-o", "--out", type=Path, default=ROOT / "output" / "SELOBJ_patched.RLC")
    parser.add_argument("--iso", type=Path, default=DEFAULT_ISO)
    parser.add_argument("--out-iso", type=Path, default=ROOT / "eldorado_menu_test.iso")
    parser.add_argument("--gdi-dir", type=Path, default=DEFAULT_GDI_DIR)
    parser.add_argument("--out-gdi-dir", type=Path, default=ROOT / "output" / "gdi_menu_test")
    parser.add_argument("--no-iso", action="store_true")
    parser.add_argument("--no-gdi", action="store_true")
    args = parser.parse_args()

    if args.show_text:
        print("=== Routage menu (SELOBJ seg 0) ===")
        for name, idx in MENU_SEGMENTS.items():
            print(f"  {name:12} -> segment {idx}")
        print("\n=== NEW GAME (segment 1) — Japanese (screenshot) ===")
        print(NEW_GAME_JP)
        print("\n=== English (test target) ===")
        print(NEW_GAME_EN)
        return

    if not args.proof and not args.swap_continue and args.new_game_en is None and not args.nuclear:
        raise SystemExit("Choose --new-game-en, --swap-continue, --proof, or --nuclear (or --show-text).")

    gdi_label: str | None = None

    src = bytearray(args.selobj.read_bytes())
    if args.nuclear:
        patch_nuclear_selobj(src)
        print("Nuclear: SELOBJ filled with 0xFF")
        if args.out == ROOT / "output" / "SELOBJ_patched.RLC":
            args.out = ROOT / "output" / "SELOBJ_nuclear.RLC"
        if args.out_gdi_dir == ROOT / "output" / "gdi_menu_test":
            args.out_gdi_dir = ROOT / "output" / "gdi_nuclear_test"
        gdi_label = "nuclear"
    elif args.new_game_en is not None:
        from selobj_menu import load_atlas_map, patch_segment_text

        atlas = load_atlas_map()
        info = patch_segment_text(
            src,
            MENU_SEGMENTS["NEW GAME"],
            args.new_game_en,
            atlas=atlas,
            clear_body_after_line1=True,
        )
        print(f"NEW GAME seg {info['segment']}: {info['old_glyphs']} glyphs -> {info['new_text']!r}")
        if info.get("clear_body_after_line1"):
            print("  cleared JP description bytecode after line 1")
        print(f"  atlas glyphs: {info.get('atlas_sample')}")
        if args.out == ROOT / "output" / "SELOBJ_patched.RLC":
            args.out = ROOT / "output" / "SELOBJ_newgame.RLC"
        if args.out_gdi_dir == ROOT / "output" / "gdi_menu_test":
            args.out_gdi_dir = ROOT / "output" / "gdi_newgame_test"
        gdi_label = "new-game-en"
    elif args.swap_continue:
        patch_copy_body(src, MENU_SEGMENTS["NEW GAME"], MENU_SEGMENTS["CONTINUE"])
        print("Swap: CONTINUE body (seg 2) -> NEW GAME (seg 1)")
        if args.out == ROOT / "output" / "SELOBJ_patched.RLC":
            args.out = ROOT / "output" / "SELOBJ_swap_continue.RLC"
        if args.out_gdi_dir == ROOT / "output" / "gdi_menu_test":
            args.out_gdi_dir = ROOT / "output" / "gdi_swap_test"
        gdi_label = "swap-continue"
    elif args.proof:
        off, n = patch_new_game_glyph(src)
        print(f"Proof flip @ {off:#x} ({n} byte) in NEW GAME segment 1")
        if args.out == ROOT / "output" / "SELOBJ_patched.RLC":
            args.out = ROOT / "output" / "SELOBJ_proof.RLC"
        if args.out_gdi_dir == ROOT / "output" / "gdi_menu_test":
            args.out_gdi_dir = ROOT / "output" / "gdi_proof_test"
        gdi_label = "proof"

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_bytes(src)
    print(f"Wrote {args.out}")

    if not args.no_iso or (not args.no_gdi and args.gdi_dir.exists()):
        write_iso_and_track3(
            args.out,
            iso_in=args.iso,
            iso_out=args.out_iso,
            gdi_dir=None if args.no_gdi else args.gdi_dir,
            gdi_out=None if args.no_gdi else args.out_gdi_dir,
            gdi_label=gdi_label,
            mirror_hack_offset=0x360C0000 if not args.no_iso else None,
        )


if __name__ == "__main__":
    main()
