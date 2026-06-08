#!/usr/bin/env python3
"""
SELOBJ.RLC main-menu text codec (Ghidra-backed).

Pipeline (no LZ on disc — FUN_8c011650 reads verbatim):
  Boot menu -> FUN_8c06af5c / FUN_8c06b092
    -> FUN_8c06b3a4(menu_x, menu_y, slot) reads ushort routing pairs in SELOBJ seg 0
    -> FUN_8c014708(slot, segment_index) attaches RLC segment from loaded selobj.rlc
    -> FUN_8c014cd0 renders text box via object VM (0x78-byte slots @ DAT_8c0150b8)

Segment roles (SELOBJ seg 0 routing pairs N,N):
  1 NEW GAME    cmd 16 — layout (03bbff2f) + inline glyph stream (u16 + attr bytes)
  2 CONTINUE    cmd 16
  3 HOME PAGE   cmd 7  — layout + 0x0E09/0x0E0F key lookups
  4 OPTION      cmd 7
  5 MEMORY CARD cmd 7

cmd 16 glyph tuple: big-endian u16 glyph_id (bytes like 9A FB -> 0x9AFB), u8 attribute.
First NEW GAME glyph in seg 1 body: 0x9AFB after ba 21 00 prefix.
"""

from __future__ import annotations

import argparse
import csv
import struct
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SELOBJ = ROOT / "disc_extracted" / "COMN" / "SELOBJ.RLC"
DEFAULT_CHAR_MAP = ROOT / "output" / "pl_char_maps.csv"
DEFAULT_GLYPH_CSV = ROOT / "output" / "selobj_glyphs.csv"

LAYOUT_MAGIC = bytes.fromhex("03bbff2f")
TEXT_PREFIX = bytes.fromhex("ba2100")  # line-open opcode before first glyph run
LINE_END = bytes.fromhex("af0310")  # observed line-break opcode in seg 1

# ASCII -> direct glyph code (same namespace as runtime char codes 0x0020..0x007A)
ASCII_CODES: dict[str, int] = {
    " ": 0x0020,
    "N": 0x004E,
    "e": 0x0065,
    "w": 0x0077,
    "G": 0x0047,
    "a": 0x0061,
    "m": 0x006D,
    "o": 0x006F,
    "n": 0x006E,
    "u": 0x0075,
    "r": 0x0072,
    "t": 0x0074,
    "i": 0x0069,
    "c": 0x0063,
    "l": 0x006C,
    "d": 0x0064,
    "s": 0x0073,
    "h": 0x0068,
    "p": 0x0070,
    "C": 0x0043,
    "O": 0x004F,
    "M": 0x004D,
    "E": 0x0045,
    "H": 0x0048,
    "P": 0x0050,
    "A": 0x0041,
    "R": 0x0052,
    "I": 0x0049,
    "Y": 0x0059,
    "g": 0x0067,
    ".": 0x002E,
    ",": 0x002C,
    "!": 0x0021,
    "?": 0x003F,
}

MENU_SEGMENTS: dict[str, int] = {
    "NEW GAME": 1,
    "CONTINUE": 2,
    "HOME PAGE": 3,
    "OPTION": 4,
    "MEMORY CARD": 5,
}

# Bytes preserved at end of cmd16 body (layout/footer markers from seg 1 tail).
CMD16_BODY_TAIL = 20


def load_atlas_map(
    char_map_csv: Path = DEFAULT_CHAR_MAP,
    glyph_csv: Path = DEFAULT_GLYPH_CSV,
) -> dict[str, int]:
    """
    char -> glyph_id (char_code) for cmd16 inline tuples.

    Primary source: pl_char_maps.csv (PL key tables, 0x004E = 'N', etc.).
    Secondary: selobj_glyphs.csv key rows (cmd7 segments, same char_code namespace).
    """
    codes: dict[str, set[int]] = {}

    def add(ch: str, code: int) -> None:
        if len(ch) == 1 and code >= 0x20:
            codes.setdefault(ch, set()).add(code)

    if char_map_csv.exists():
        with char_map_csv.open(encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                for ck, cc in (("char_a", "char_a_code"), ("char_b", "char_b_code")):
                    ch = row.get(ck, "")
                    raw = row.get(cc, "")
                    if ch and raw:
                        add(ch, int(raw, 16))

    if glyph_csv.exists():
        with glyph_csv.open(encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                if row.get("source") != "key":
                    continue
                ch = row.get("char", "")
                raw = row.get("char_code", "")
                if ch and raw:
                    add(ch, int(raw, 16))

    atlas: dict[str, int] = {}
    for ch, opts in codes.items():
        ascii_pref = {c for c in opts if c < 0x80}
        atlas[ch] = min(ascii_pref) if ascii_pref else min(opts)
    for ch, code in ASCII_CODES.items():
        atlas.setdefault(ch, code)
    return atlas


@dataclass
class Segment:
    index: int
    offset: int
    meta: int
    payload: bytes


@dataclass
class GlyphToken:
    code: int
    attr: int
    raw: bytes


def parse_rlc(data: bytes) -> list[Segment]:
    count = struct.unpack_from("<I", data, 0)[0]
    rows: list[tuple[int, int]] = []
    for i in range(count):
        off = struct.unpack_from("<I", data, 4 + i * 8)[0]
        meta = struct.unpack_from("<I", data, 8 + i * 8)[0]
        rows.append((off, meta))
    segments: list[Segment] = []
    for i, (off, meta) in enumerate(rows):
        end = rows[i + 1][0] if i + 1 < count else len(data)
        segments.append(Segment(i, off, meta, data[off:end]))
    return segments


def segment_body(seg: Segment) -> bytes:
    if not seg.payload:
        return b""
    if seg.payload[0] == 0x80:
        return seg.payload[5:]
    if len(seg.payload) >= 4:
        return seg.payload[4:]
    return seg.payload


def find_text_run_start(body: bytes) -> int:
    pos = body.find(TEXT_PREFIX)
    if pos >= 0:
        return pos + len(TEXT_PREFIX)
    pos = body.find(LAYOUT_MAGIC)
    if pos >= 0:
        dash = body.find(bytes.fromhex("2d002d"), pos)
        if dash >= 0:
            return dash + 4
    return -1


def find_text_run_end(body: bytes, start: int) -> int:
    pos = body.find(LINE_END, start)
    if pos > start:
        return pos
    pos = body.find(bytes.fromhex("af03"), start)
    if pos > start:
        return pos
    return start


def decode_cmd16_glyphs(body: bytes) -> tuple[int, list[GlyphToken]]:
    start = find_text_run_start(body)
    if start < 0:
        return -1, []

    end = find_text_run_end(body, start)
    tokens: list[GlyphToken] = []
    pos = start
    while pos + 2 < end:
        if body[pos] == 0x00:
            pos += 1
            continue

        code = (body[pos] << 8) | body[pos + 1]
        attr = body[pos + 2]
        raw = body[pos : pos + 3]
        tokens.append(GlyphToken(code=code, attr=attr, raw=raw))
        pos += 3
    return start, tokens


def encode_glyphs(
    chars: str,
    *,
    atlas: dict[str, int] | None = None,
    first_attr: int = 0x20,
    rest_attr: int = 0x00,
) -> bytes:
    table = atlas or load_atlas_map()
    out = bytearray()
    for i, ch in enumerate(chars):
        code = table.get(ch)
        if code is None:
            raise ValueError(f"Unsupported character {ch!r} (not in atlas map)")
        attr = first_attr if i == 0 else rest_attr
        out.extend(bytes([(code >> 8) & 0xFF, code & 0xFF, attr]))
    return bytes(out)


def patch_segment_text(
    data: bytearray,
    seg_index: int,
    new_text: str,
    *,
    atlas: dict[str, int] | None = None,
    clear_body_after_line1: bool = False,
) -> dict:
    segments = parse_rlc(data)
    seg = segments[seg_index]
    payload = bytearray(seg.payload)
    body = bytearray(segment_body(seg))

    start, old_tokens = decode_cmd16_glyphs(body)
    if start < 0:
        raise ValueError(f"Could not locate text run in segment {seg_index}")

    end = find_text_run_end(body, start)
    if end <= start:
        raise ValueError(f"Could not locate line end in segment {seg_index}")

    prefix = bytes(body[:start])
    suffix = bytes(body[end:])
    encoded = encode_glyphs(new_text, atlas=atlas)

    if clear_body_after_line1:
        # cmd16 stores the visible description after the first af0310 line break.
        tail_keep = body[-CMD16_BODY_TAIL:] if len(body) >= CMD16_BODY_TAIL else b""
        post_start = end + len(LINE_END)
        first_line = encoded + LINE_END
        slot = post_start - start
        if len(first_line) > slot:
            # Allow eating into the post-line bytecode when clearing it anyway.
            post_start += len(first_line) - slot
        elif len(first_line) < slot:
            first_line = first_line + bytes(slot - len(first_line))
        post_len = max(0, len(body) - post_start - len(tail_keep))
        cleared = bytes(post_len)
        new_body = prefix + first_line + cleared + tail_keep
        if len(new_body) != len(body):
            raise ValueError(
                f"cmd16 body size mismatch seg {seg_index}: "
                f"{len(new_body)} != {len(body)}"
            )
    else:
        slot = end - start
        if len(encoded) > slot:
            raise ValueError(
                f"Encoded text ({len(encoded)} B) exceeds first-line slot ({slot} B) "
                f"in segment {seg_index}; use --clear-body or shorter text"
            )
        if len(encoded) < slot:
            encoded = encoded + bytes(slot - len(encoded))
        new_body = prefix + encoded + suffix

    if seg.payload[0] == 0x80:
        payload[5:] = new_body
    else:
        payload[4:] = new_body

    data[seg.offset : seg.offset + len(payload)] = payload
    return {
        "segment": seg_index,
        "text_start": start,
        "old_glyphs": len(old_tokens),
        "old_bytes": end - start,
        "new_bytes": len(encoded),
        "new_text": new_text,
        "clear_body_after_line1": clear_body_after_line1,
        "atlas_sample": {
            ch: f"{encode_glyphs(ch, atlas=atlas)[:2].hex()}"
            for ch in sorted(set(new_text))
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selobj", type=Path, default=DEFAULT_SELOBJ)
    parser.add_argument("--decode", action="store_true", help="Decode cmd16 menu segments 1-2")
    parser.add_argument("--show-atlas", metavar="TEXT", help="Print atlas glyph IDs for TEXT")
    parser.add_argument("--patch-new-game", metavar="TEXT", help='Replace NEW GAME description (e.g. "New Game")')
    parser.add_argument(
        "--clear-body",
        action="store_true",
        help="Zero cmd16 bytecode after first line break (drops JP description blob)",
    )
    parser.add_argument("-o", "--out", type=Path, default=ROOT / "output" / "SELOBJ_newgame.RLC")
    args = parser.parse_args()

    atlas = load_atlas_map()

    if args.show_atlas:
        for ch in args.show_atlas:
            code = atlas.get(ch)
            print(f"  {ch!r} -> {code:#06x}" if code else f"  {ch!r} -> MISSING")
        return

    data = bytearray(args.selobj.read_bytes())

    if args.decode:
        for name, idx in MENU_SEGMENTS.items():
            if idx > 2:
                continue
            body = segment_body(parse_rlc(data)[idx])
            start, tokens = decode_cmd16_glyphs(body)
            print(f"=== {name} (seg {idx}) ===")
            print(f"  text_start={start} glyphs={len(tokens)}")
            sample = " ".join(f"{t.code:#06x}/{t.attr:#04x}" for t in tokens[:20])
            print(f"  head: {sample}")
        return

    if args.patch_new_game:
        info = patch_segment_text(
            data,
            MENU_SEGMENTS["NEW GAME"],
            args.patch_new_game,
            atlas=atlas,
            clear_body_after_line1=args.clear_body,
        )
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_bytes(data)
        print(f"Patched NEW GAME seg {info['segment']}: {info['old_glyphs']} glyphs -> {info['new_text']!r}")
        print(f"  bytes {info['old_bytes']} -> {info['new_bytes']}")
        if info.get("clear_body_after_line1"):
            print("  cleared post-line1 bytecode blob")
        print(f"  atlas: {info.get('atlas_sample')}")
        print(f"Wrote {args.out}")
        return

    raise SystemExit("Use --decode or --patch-new-game TEXT")


if __name__ == "__main__":
    main()
