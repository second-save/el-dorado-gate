#!/usr/bin/env python3
"""
Extract glyph tables from El Dorado Gate DPFONT/*.DAT and COMN/PL*.RLC.

Reverse-engineering notes (1ST_READ.BIN @ 0x8C010000):

  FUN_8c018f48(param_1=mode, param_2=code) dispatches font tables:
    mode 1 — mono-byte: PTR_PTR_8c019068 → pl00.rlc … pl2e.rlc @ 0x8C0B06E0
    mode 2 — dual-tile: em_*.tlp tables @ 0x8C0B08A0 / 0x8C0B0A3C
    else   — 8-byte tiles: lm*.tlp @ 0x8C0B07A0

  DPFONT/S{18,20,24,26}RM04P.DAT are 4bpp horizontal atlases (height = point size).
  PL*.RLC segment 0 maps encoded keys → character codes; other segments hold
  per-glyph metrics referencing atlas_x in the DPFONT strip.

  Glyph record layout (42 bytes, segment payload offset 6):
    u16 width, u16 height, u16 atlas_x, u16 advance, u16 flags, …
"""

from __future__ import annotations

import argparse
import csv
import struct
from dataclasses import dataclass
from pathlib import Path

try:
    from PIL import Image
except ImportError as exc:  # pragma: no cover
    raise SystemExit("pip install pillow") from exc

ROOT = Path(__file__).resolve().parents[1]
DISC = ROOT / "disc_extracted"
DPFONT_DIR = DISC / "DPFONT"
COMN_DIR = DISC / "COMN"
FIRST_READ = DISC / "1ST_READ.BIN"
BASE_VA = 0x8C010000

FONT_FILES = {
    18: "S18RM04P.DAT",
    20: "S20RM04P.DAT",
    24: "S24RM04P.DAT",
    26: "S26RM04P.DAT",
}

GLYPH_RECORD_SIZE = 42
MIN_GLYPH_SCORE = 200


@dataclass
class CharMapEntry:
    key_a: int
    char_a: int
    key_b: int
    char_b: int


@dataclass
class GlyphRecord:
    pl_file: str
    segment_index: int
    seg_id: int
    page: int
    rec_index: int
    width: int
    height: int
    atlas_x: int
    advance: int
    flags: int
    score: int


def va_to_offset(va: int) -> int:
    return va - BASE_VA


def load_mode1_pl_table() -> list[tuple[int, str]]:
    """Pointers from FUN_8c018f48 mode-1 table @ 0x8C0B06E0."""
    data = FIRST_READ.read_bytes()
    table_va = struct.unpack_from("<I", data, va_to_offset(0x8C019068))[0]
    table_off = va_to_offset(table_va)
    names: list[tuple[int, str]] = []
    for i in range(64):
        ptr = struct.unpack_from("<I", data, table_off + i * 4)[0]
        if ptr == 0:
            continue
        str_off = va_to_offset(ptr)
        end = data.find(b"\x00", str_off)
        if end < str_off:
            continue
        name = data[str_off:end].decode("ascii", errors="replace")
        if name:
            names.append((i, name))
    return names


def parse_rlc_segments(data: bytes) -> list[bytes]:
    if len(data) < 8:
        return []
    count = struct.unpack_from("<I", data, 0)[0]
    if count > 10_000 or 4 + count * 8 > len(data):
        return []
    segments: list[bytes] = []
    for i in range(count):
        off = struct.unpack_from("<I", data, 4 + i * 8)[0]
        end = struct.unpack_from("<I", data, 4 + (i + 1) * 8)[0] if i + 1 < count else len(data)
        if off >= len(data) or end <= off:
            continue
        segments.append(data[off:end])
    return segments


def parse_char_map(seg0: bytes) -> list[CharMapEntry]:
    if len(seg0) < 10 or seg0[:4] != b"\x80\x00\x01\x10":
        return []
    count = struct.unpack_from("<H", seg0, 8)[0]
    entries: list[CharMapEntry] = []
    pos = 10
    for _ in range(count):
        if pos + 8 > len(seg0):
            break
        a, b, c, d = struct.unpack_from("<4H", seg0, pos)
        entries.append(CharMapEntry(a, b, c, d))
        pos += 8
    return entries


def atlas_width(data: bytes, height: int) -> int:
    return (len(data) * 2) // height


def glyph_score(data: bytes, height: int, atlas_x: int, width: int) -> int:
    row_bytes = (atlas_width(data, height) + 1) // 2
    score = 0
    for y in range(height):
        for px in range(width):
            pos = y * row_bytes + (atlas_x + px) // 2
            if pos >= len(data):
                continue
            nib = (data[pos] >> 4) if (atlas_x + px) % 2 == 0 else (data[pos] & 0x0F)
            score += nib
    return score


def parse_glyph_records(
    pl_file: str,
    segment_index: int,
    payload: bytes,
    font_data: bytes,
    font_height: int,
) -> list[GlyphRecord]:
    if len(payload) < 6:
        return []
    seg_id = struct.unpack_from("<I", payload, 0)[0]
    page = struct.unpack_from("<H", payload, 4)[0]
    body = payload[6:]
    max_x = atlas_width(font_data, font_height)
    records: list[GlyphRecord] = []
    for i in range(len(body) // GLYPH_RECORD_SIZE):
        rec = body[i * GLYPH_RECORD_SIZE : (i + 1) * GLYPH_RECORD_SIZE]
        width, height, atlas_x, advance, flags = struct.unpack_from("<5H", rec, 0)
        if not (4 <= width <= 48 and atlas_x < max_x):
            continue
        score = glyph_score(font_data, font_height, atlas_x, width)
        if score < MIN_GLYPH_SCORE:
            continue
        records.append(
            GlyphRecord(
                pl_file=pl_file,
                segment_index=segment_index,
                seg_id=seg_id,
                page=page,
                rec_index=i,
                width=width,
                height=height,
                atlas_x=atlas_x,
                advance=advance,
                flags=flags,
                score=score,
            )
        )
    return records


def render_atlas_preview(data: bytes, height: int, max_width: int = 4096) -> Image.Image:
    width_px = atlas_width(data, height)
    row_bytes = (width_px + 1) // 2
    img = Image.new("L", (width_px, height), 0)
    px = img.load()
    for y in range(height):
        row_base = y * row_bytes
        for x in range(width_px):
            pos = row_base + x // 2
            if pos >= len(data):
                break
            nib = (data[pos] >> 4) if x % 2 == 0 else (data[pos] & 0x0F)
            px[x, y] = nib * 17
    if width_px > max_width:
        img = img.resize((max_width, height))
    return img


def crop_glyph(data: bytes, height: int, atlas_x: int, width: int) -> Image.Image:
    row_bytes = (atlas_width(data, height) + 1) // 2
    img = Image.new("L", (width, height), 0)
    px = img.load()
    for y in range(height):
        for x in range(width):
            pos = y * row_bytes + (atlas_x + x) // 2
            if pos >= len(data):
                continue
            nib = (data[pos] >> 4) if (atlas_x + x) % 2 == 0 else (data[pos] & 0x0F)
            px[x, y] = nib * 17
    return img


def char_label(code: int) -> str:
    if code < 0x20:
        return f"U+{code:04X}"
    if code < 0x7F:
        return chr(code)
    if 0x8140 <= code <= 0xFCFF:
        try:
            return bytes([(code >> 8) & 0xFF, code & 0xFF]).decode("shift_jis")
        except UnicodeDecodeError:
            return f"U+{code:04X}"
    return f"U+{code:04X}"


def export_all(
    out_dir: Path,
    font_height: int = 18,
    export_png: bool = False,
    pl_glob: str = "PL*.RLC",
) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    glyph_dir = out_dir / "glyphs"
    atlas_dir = out_dir / "atlases"
    atlas_dir.mkdir(parents=True, exist_ok=True)
    if export_png:
        glyph_dir.mkdir(parents=True, exist_ok=True)

    font_path = DPFONT_DIR / FONT_FILES[font_height]
    font_data = font_path.read_bytes()

    preview = render_atlas_preview(font_data, font_height)
    preview.save(atlas_dir / f"S{font_height}_atlas_preview.png")

    pl_files = sorted(COMN_DIR.glob(pl_glob))
    if not pl_files:
        pl_files = sorted(COMN_DIR.glob("PL*.RLC"))

    char_rows: list[dict] = []
    glyph_rows: list[dict] = []

    for pl_path in pl_files:
        segments = parse_rlc_segments(pl_path.read_bytes())
        if not segments:
            continue
        for idx, entry in enumerate(parse_char_map(segments[0])):
            char_rows.append(
                {
                    "pl_file": pl_path.name,
                    "entry_index": idx,
                    "key_a": f"0x{entry.key_a:04X}",
                    "char_a": char_label(entry.char_a),
                    "char_a_code": f"0x{entry.char_a:04X}",
                    "key_b": f"0x{entry.key_b:04X}",
                    "char_b": char_label(entry.char_b),
                    "char_b_code": f"0x{entry.char_b:04X}",
                }
            )
        for seg_index, payload in enumerate(segments[1:], start=1):
            for rec in parse_glyph_records(
                pl_path.name, seg_index, payload, font_data, font_height
            ):
                glyph_rows.append(
                    {
                        "pl_file": rec.pl_file,
                        "segment_index": rec.segment_index,
                        "seg_id": rec.seg_id,
                        "page": f"0x{rec.page:04X}",
                        "rec_index": rec.rec_index,
                        "width": rec.width,
                        "height": rec.height,
                        "atlas_x": rec.atlas_x,
                        "advance": rec.advance,
                        "flags": f"0x{rec.flags:04X}",
                        "score": rec.score,
                        "font": f"S{font_height}",
                    }
                )
                if export_png:
                    img = crop_glyph(font_data, font_height, rec.atlas_x, rec.width)
                    fname = (
                        f"{rec.pl_file}_s{rec.segment_index}_r{rec.rec_index}"
                        f"_x{rec.atlas_x}_w{rec.width}.png"
                    )
                    img.save(glyph_dir / fname)

    # EN_OBJ*.RLC use the same glyph metrics layout (enemy/object names).
    for obj_path in sorted(COMN_DIR.glob("EN_OBJ*.RLC")):
        segments = parse_rlc_segments(obj_path.read_bytes())
        for seg_index, payload in enumerate(segments[1:], start=1):
            for rec in parse_glyph_records(
                obj_path.name, seg_index, payload, font_data, font_height
            ):
                glyph_rows.append(
                    {
                        "pl_file": rec.pl_file,
                        "segment_index": rec.segment_index,
                        "seg_id": rec.seg_id,
                        "page": f"0x{rec.page:04X}",
                        "rec_index": rec.rec_index,
                        "width": rec.width,
                        "height": rec.height,
                        "atlas_x": rec.atlas_x,
                        "advance": rec.advance,
                        "flags": f"0x{rec.flags:04X}",
                        "score": rec.score,
                        "font": f"S{font_height}",
                    }
                )

    mode1_rows = [{"mode1_index": idx, "pl_filename": name} for idx, name in load_mode1_pl_table()]

    def write_csv(name: str, rows: list[dict], fields: list[str]) -> Path:
        path = out_dir / name
        with path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)
        return path

    char_csv = write_csv(
        "pl_char_maps.csv",
        char_rows,
        [
            "pl_file",
            "entry_index",
            "key_a",
            "char_a",
            "char_a_code",
            "key_b",
            "char_b",
            "char_b_code",
        ],
    )
    glyph_csv = write_csv(
        f"dpfont_glyphs_S{font_height}.csv",
        glyph_rows,
        [
            "pl_file",
            "segment_index",
            "seg_id",
            "page",
            "rec_index",
            "width",
            "height",
            "atlas_x",
            "advance",
            "flags",
            "score",
            "font",
        ],
    )
    mode_csv = write_csv(
        "fun_8c018f48_mode1_table.csv",
        mode1_rows,
        ["mode1_index", "pl_filename"],
    )

    print(f"Font atlas : {font_path.name} ({atlas_width(font_data, font_height)}x{font_height} 4bpp)")
    print(f"Char maps  : {len(char_rows)} entries -> {char_csv}")
    print(f"Glyph recs : {len(glyph_rows)} entries -> {glyph_csv}")
    print(f"Mode1 table: {len(mode1_rows)} slots  -> {mode_csv}")
    if export_png:
        print(f"Glyph PNGs : {glyph_dir}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Extract DPFONT glyph tables for El Dorado Gate.")
    parser.add_argument(
        "--out",
        type=Path,
        default=ROOT / "output",
        help="Output directory (default: output/)",
    )
    parser.add_argument(
        "--font-size",
        type=int,
        choices=sorted(FONT_FILES),
        default=18,
        help="DPFONT point size (default: 18)",
    )
    parser.add_argument(
        "--all-fonts",
        action="store_true",
        help="Extract glyph metrics for all four DPFONT sizes",
    )
    parser.add_argument(
        "--png",
        action="store_true",
        help="Export individual glyph PNG crops (slow, large)",
    )
    parser.add_argument(
        "--pl-glob",
        default="PL*.RLC",
        help="Glob under COMN/ for palette RLC files (default: PL*.RLC)",
    )
    args = parser.parse_args()

    if args.all_fonts:
        combined: list[dict] = []
        for size in sorted(FONT_FILES):
            export_all(args.out, font_height=size, export_png=args.png, pl_glob=args.pl_glob)
            path = args.out / f"dpfont_glyphs_S{size}.csv"
            with path.open(encoding="utf-8") as fh:
                reader = csv.DictReader(fh)
                combined.extend(reader)
        combined_path = args.out / "dpfont_glyphs.csv"
        fields = [
            "pl_file",
            "segment_index",
            "seg_id",
            "page",
            "rec_index",
            "width",
            "height",
            "atlas_x",
            "advance",
            "flags",
            "score",
            "font",
        ]
        with combined_path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fields)
            writer.writeheader()
            writer.writerows(combined)
        print(f"Combined   : {len(combined)} entries -> {combined_path}")
    else:
        export_all(args.out, font_height=args.font_size, export_png=args.png, pl_glob=args.pl_glob)
        per_font = args.out / f"dpfont_glyphs_S{args.font_size}.csv"
        combined_path = args.out / "dpfont_glyphs.csv"
        if per_font.exists():
            combined_path.write_bytes(per_font.read_bytes())


if __name__ == "__main__":
    main()
