#!/usr/bin/env python3
"""
Decode El Dorado Gate dialogue bytecode via PL char maps and DPFONT glyph tables.

Pipeline (mirrors FUN_8c018f48 / FUN_8c018fca / FUN_8c01927a):
  dialogue bytes → u16 key lookup (pl_char_maps.csv) → char_code
                 → glyph metrics (dpfont_glyphs_*.csv) → atlas_x
                 + inline Shift-JIS literals in the bytecode stream
"""

from __future__ import annotations

import argparse
import csv
import json
import struct
from dataclasses import dataclass, field
from pathlib import Path

from pl_runtime import (
    GlyphMetric,
    SceneContext,
    build_scene_context,
    export_cmd26_csv,
    pl_index_to_name,
    resolve_pl_path,
)
from rlc_decode import CMD_NAMES, parse_rlc

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CHAR_MAP = ROOT / "output" / "pl_char_maps.csv"
DEFAULT_MODE1 = ROOT / "output" / "fun_8c018f48_mode1_table.csv"

SKIP_SEQ = (
    b"\x1f\x00",
    b"\x80\x00",
    b"\x00\x1f",
    b"\x00\x00",
)
CONTROL_BYTES = frozenset({0x1F, 0xBF, 0xFF})


@dataclass
class DecodedChar:
    char: str
    source: str  # key | sjis | code
    key: int | None = None
    char_code: int | None = None
    atlas_x: int | None = None
    width: int | None = None
    pl_file: str | None = None


@dataclass
class DecodeResult:
    text: str
    chars: list[DecodedChar] = field(default_factory=list)
    pl_file: str = "PL00.RLC"
    notes: list[str] = field(default_factory=list)


def load_mode1_table(path: Path) -> dict[int, str]:
    table: dict[int, str] = {}
    with path.open(encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            table[int(row["mode1_index"])] = row["pl_filename"].upper().replace(".RLC", ".RLC")
    return table


def load_char_maps(path: Path) -> dict[str, dict[int, int]]:
    maps: dict[str, dict[int, int]] = {}
    with path.open(encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            pf = row["pl_file"]
            slot = maps.setdefault(pf, {})
            slot[int(row["key_a"], 16)] = int(row["char_a_code"], 16)
            slot[int(row["key_b"], 16)] = int(row["char_b_code"], 16)
    return maps


def pl_name_from_index(index: int, mode1: dict[int, str]) -> str:
    name = mode1.get(index, "pl00.rlc")
    return name.upper().replace(".RLC", ".RLC")


def is_sjis_lead(byte: int) -> bool:
    return 0x81 <= byte <= 0x9F or 0xE0 <= byte <= 0xFC


def is_sjis_trail(byte: int) -> bool:
    return 0x40 <= byte <= 0xFC


def is_printable_jp(ch: str) -> bool:
    if not ch or len(ch) != 1:
        return False
    o = ord(ch)
    if 0x3040 <= o <= 0x9FFF:
        return True
    if 0x3000 <= o <= 0x303F:
        return True
    if 0xFF01 <= o <= 0xFFEF:
        return True
    if 0x20 <= o < 0x7F:
        return True
    return False


def code_to_char(code: int) -> str:
    if code < 0x20:
        return ""
    if code < 0x7F:
        return chr(code)
    if 0xA1 <= code <= 0xDF:
        try:
            return bytes([code]).decode("shift_jis")
        except UnicodeDecodeError:
            return ""
    hi = (code >> 8) & 0xFF
    lo = code & 0xFF
    if is_sjis_lead(hi) and is_sjis_trail(lo):
        try:
            return bytes([hi, lo]).decode("shift_jis")
        except UnicodeDecodeError:
            pass
    if is_sjis_lead(lo) and is_sjis_trail(hi):
        try:
            return bytes([lo, hi]).decode("shift_jis")
        except UnicodeDecodeError:
            pass
    return ""


def glyph_to_char(glyph: GlyphMetric | None) -> tuple[int | None, int | None]:
    if glyph is None:
        return None, None
    return glyph.atlas_x, glyph.width or None


def skip_controls(data: bytes, pos: int) -> int:
    while pos < len(data):
        advanced = False
        for seq in SKIP_SEQ:
            if data.startswith(seq, pos):
                pos += len(seq)
                advanced = True
                break
        if advanced:
            continue
        if data[pos] in CONTROL_BYTES:
            pos += 1
            continue
        if data[pos] == 0x00:
            pos += 1
            continue
        break
    return pos


def decode_stream(
    body: bytes,
    scene: SceneContext,
    mode1: dict[int, str],
) -> DecodeResult:
    chars: list[DecodedChar] = []
    pos = 0
    # Skip common dialogue prefix: u16 id, 1f00, 1e00, optional 22 marker
    if len(body) >= 8 and body[2:4] == b"\x1f\x00":
        pos = 8
        if pos < len(body) and body[pos] == 0x22:
            pos += 1

    while pos < len(body):
        if pos + 3 < len(body) and body[pos : pos + 3] == b"\x1f\x00\x80":
            name = pl_index_to_name(body[pos + 3], mode1)
            if name:
                scene.switch(name)
            pos += 4
            continue

        pos = skip_controls(body, pos)
        if pos >= len(body):
            break

        if is_sjis_lead(body[pos]) and pos + 1 < len(body) and is_sjis_trail(body[pos + 1]):
            try:
                raw = body[pos : pos + 2]
                ch = raw.decode("shift_jis")
                if not is_printable_jp(ch):
                    pos += 1
                    continue
                code = (raw[0] << 8) | raw[1]
                ch, glyph, pl_used = scene.resolve_sjis(raw[0], raw[1])
                if not ch:
                    ch = raw.decode("shift_jis")
                atlas_x, width = glyph_to_char(glyph)
                chars.append(
                    DecodedChar(
                        char=ch,
                        source="sjis",
                        char_code=code,
                        atlas_x=atlas_x,
                        width=width,
                        pl_file=pl_used,
                    )
                )
                pos += 2
                continue
            except UnicodeDecodeError:
                pass

        if pos + 1 < len(body):
            key = struct.unpack_from("<H", body, pos)[0]
            if key not in (0, 0xFFFF):
                pl_used, code = scene.lookup_key(key)
                if pl_used is not None and code is not None:
                    ch, glyph = scene.resolve_code(pl_used, code)
                    if not ch:
                        ch = code_to_char(code)
                    if ch and (is_printable_jp(ch) or ch == "\u25a1"):
                        atlas_x, width = glyph_to_char(glyph)
                        chars.append(
                            DecodedChar(
                                char=ch,
                                source="key" if code < 0x4000 else "slot",
                                key=key,
                                char_code=code,
                                atlas_x=atlas_x,
                                width=width,
                                pl_file=pl_used,
                            )
                        )
                        pos += 2
                        continue

        pos += 1

    text = "".join(c.char for c in chars)
    notes: list[str] = []
    key_n = sum(1 for c in chars if c.source == "key")
    slot_n = sum(1 for c in chars if c.source == "slot")
    sjis_n = sum(1 for c in chars if c.source == "sjis")
    atlas_n = sum(1 for c in chars if c.atlas_x is not None)
    pl_used = sorted({c.pl_file for c in chars if c.pl_file})
    if len(scene.pl_files) > 1:
        notes.append(f"pl_refs={'+'.join(scene.pl_files)}")
    if scene.switches:
        notes.append(f"pl_switch={scene.switches}")
    if pl_used:
        notes.append(f"pl_used={'+'.join(pl_used)}")
    if key_n:
        notes.append(f"keys={key_n}")
    if slot_n:
        notes.append(f"slots={slot_n}")
    if sjis_n:
        notes.append(f"sjis={sjis_n}")
    if atlas_n:
        notes.append(f"atlas={atlas_n}")
    primary = scene.active if scene.active in scene.runtimes else scene.pl_files[0]
    return DecodeResult(text=text, chars=chars, pl_file=primary, notes=notes)


def guess_pl_file(body: bytes, mode1: dict[int, str], char_maps: dict[str, dict[int, int]]) -> str:
    if len(body) >= 2:
        idx = struct.unpack_from("<H", body, 0)[0]
        if idx in mode1:
            return pl_name_from_index(idx, mode1)
    best = "PL00.RLC"
    best_hits = -1
    for pf, kmap in char_maps.items():
        if not pf.startswith("PL"):
            continue
        hits = 0
        for pos in range(0, min(len(body), 512) - 1, 2):
            if struct.unpack_from("<H", body, pos)[0] in kmap:
                hits += 1
        if hits > best_hits:
            best_hits = hits
            best = pf
    return best


def decode_segment(
    payload: bytes,
    char_maps: dict[str, dict[int, int]],
    mode1: dict[int, str],
    char_map_csv: Path,
    pl_override: str | None = None,
) -> DecodeResult | None:
    if len(payload) < 4:
        return None
    cmd = struct.unpack_from("<I", payload, 0)[0]
    if cmd not in (6, 7):
        return None
    body = payload[4:]
    scene = build_scene_context(body, mode1, char_maps, char_map_csv)
    if pl_override and resolve_pl_path(pl_override):
        scene.active = pl_override
    return decode_stream(body, scene, mode1)


def decode_file(
    path: Path,
    char_maps: dict[str, dict[int, int]],
    mode1: dict[int, str],
    char_map_csv: Path,
) -> list[dict]:
    rows: list[dict] = []
    for seg in parse_rlc(path.read_bytes()):
        result = decode_segment(seg.payload, char_maps, mode1, char_map_csv)
        if result is None:
            continue
        jp_chars = sum(1 for c in result.text if "\u3040" <= c <= "\u9fff")
        rows.append(
            {
                "source_file": str(path),
                "segment_index": seg.index,
                "segment_offset": f"0x{seg.offset:X}",
                "kind": CMD_NAMES.get(struct.unpack_from("<I", seg.payload, 0)[0], "dialogue"),
                "pl_file": result.pl_file,
                "text_jp": result.text,
                "jp_char_count": jp_chars,
                "char_count": len(result.chars),
                "notes": "; ".join(result.notes),
                "glyph_trace": json.dumps(
                    [
                        {
                            "ch": c.char,
                            "src": c.source,
                            "key": f"0x{c.key:04X}" if c.key is not None else "",
                            "code": f"0x{c.char_code:04X}" if c.char_code is not None else "",
                            "atlas_x": c.atlas_x if c.atlas_x is not None else "",
                            "width": c.width if c.width is not None else "",
                        }
                        for c in result.chars[:200]
                    ],
                    ensure_ascii=False,
                ),
            }
        )
    return rows


def export_glyph_rows(dialogue_rows: list[dict], out_csv: Path) -> None:
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "source_file",
        "segment_index",
        "pl_file",
        "char_index",
        "char",
        "source",
        "key",
        "char_code",
        "atlas_x",
        "width",
    ]
    flat: list[dict] = []
    for row in dialogue_rows:
        trace = json.loads(row["glyph_trace"])
        for i, item in enumerate(trace):
            flat.append(
                {
                    "source_file": row["source_file"],
                    "segment_index": row["segment_index"],
                    "pl_file": row["pl_file"],
                    "char_index": i,
                    "char": item["ch"],
                    "source": item["src"],
                    "key": item["key"],
                    "char_code": item["code"],
                    "atlas_x": item["atlas_x"],
                    "width": item["width"],
                }
            )
    with out_csv.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(flat)


def export_csv(rows: list[dict], out_csv: Path) -> None:
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "source_file",
        "segment_index",
        "segment_offset",
        "kind",
        "pl_file",
        "text_jp",
        "jp_char_count",
        "char_count",
        "notes",
        "glyph_trace",
    ]
    with out_csv.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="RLC file or directory")
    parser.add_argument("-o", "--csv", type=Path, default=ROOT / "output" / "dialogue_decoded.csv")
    parser.add_argument("--char-map", type=Path, default=DEFAULT_CHAR_MAP)
    parser.add_argument("--mode1", type=Path, default=DEFAULT_MODE1)
    parser.add_argument(
        "--runtime-out",
        type=Path,
        default=ROOT / "output" / "pl_runtime_slots.csv",
        help="Export PL runtime slot tables",
    )
    parser.add_argument(
        "--cmd26-out",
        type=Path,
        default=ROOT / "output" / "pl_cmd26_tables.csv",
        help="Export parsed cmd 26 runtime table pairs per PL",
    )
    parser.add_argument(
        "--glyphs-out",
        type=Path,
        default=ROOT / "output" / "dialogue_glyphs.csv",
        help="Flat per-character trace CSV",
    )
    args = parser.parse_args()

    char_maps = load_char_maps(args.char_map)
    mode1 = load_mode1_table(args.mode1)

    from pl_runtime import export_runtime_csv

    export_runtime_csv(args.runtime_out, args.char_map)
    export_cmd26_csv(args.cmd26_out, args.char_map)

    paths = sorted(args.input.rglob("*.RLC")) if args.input.is_dir() else [args.input]
    rows: list[dict] = []
    for path in paths:
        rows.extend(decode_file(path, char_maps, mode1, args.char_map))

    export_csv(rows, args.csv)
    export_glyph_rows(rows, args.glyphs_out)
    with_jp = sum(1 for r in rows if r["jp_char_count"] > 0)
    keyed = sum(1 for r in rows if "keys=" in r["notes"])
    atlas = sum(1 for r in rows if "atlas=" in r["notes"])
    print(
        f"Decoded {len(rows)} dialogue segments ({with_jp} with kanana/kanji, "
        f"{keyed} with key lookups, {atlas} with atlas_x)"
    )
    print(f"  text    -> {args.csv}")
    print(f"  trace   -> {args.glyphs_out}")
    print(f"  runtime -> {args.runtime_out}")
    print(f"  cmd26   -> {args.cmd26_out}")


if __name__ == "__main__":
    main()
