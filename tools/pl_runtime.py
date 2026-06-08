#!/usr/bin/env python3
"""
Build per-PL runtime glyph tables (FUN_8c0191be / FUN_8c018fca).

Sources in each COMN/PL*.RLC:
  - 42-byte glyph metrics (segments 1+, offset 6) → slot 0x4000+N
  - cmd 35 segment → SJIS index → atlas_x ushort table (offset 6 + jis_index)
  - cmd 26 segment → FUN_8c0191be ushort (index, value) runtime overlays
  - segment page == SJIS lead byte → rec_index (trail - 0x40) → atlas_x
  - pl_char_maps.csv → key→code and code→display for proprietary slots
"""

from __future__ import annotations

import csv
import struct
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMN = ROOT / "disc_extracted" / "COMN"
DPFONT = ROOT / "disc_extracted" / "DPFONT"
GLYPH_RECORD_SIZE = 42
CMD_SJIS_TABLE = 35
CMD_RUNTIME_BULK = 26
SLOT_BASE = 0x4000
SLOT_PLACEHOLDER = "\u25a1"
MIN_GLYPH_SCORE = 8
SJIS_FALLBACK_PLS = (
    "PL0D.RLC",
    "PL10.RLC",
    "PL0F.RLC",
    "PL19.RLC",
    "PL00.RLC",
)


@dataclass
class GlyphMetric:
    atlas_x: int
    width: int
    height: int
    segment_index: int
    page: int
    rec_index: int


@dataclass
class RuntimeTable:
    offset: int
    count: int
    pairs: list[tuple[int, int]]
    sjis_hits: int = 0
    slot_hits: int = 0


@dataclass
class PlRuntime:
    pl_file: str
    slots: dict[int, GlyphMetric]
    code_display: dict[int, str]
    code_aliases: dict[int, int]
    sjis_metrics: dict[int, GlyphMetric]
    page_tables: dict[int, dict[int, GlyphMetric]]
    cmd26_tables: list[RuntimeTable]
    sjis_overlay: dict[int, GlyphMetric]

    def resolve_code(self, code: int) -> tuple[str, GlyphMetric | None]:
        code = self.code_aliases.get(code, code)
        glyph = self.slots.get(code)
        if glyph is None and code in self.code_display:
            return self.code_display[code], None
        if glyph is not None:
            ch = self.code_display.get(code)
            if not ch:
                ch = SLOT_PLACEHOLDER
            return ch, glyph
        if code in self.code_display:
            return self.code_display[code], self.slots.get(code)
        return "", None

    def resolve_sjis(self, lead: int, trail: int) -> tuple[str, GlyphMetric | None]:
        code = (lead << 8) | trail
        try:
            ch = bytes([lead, trail]).decode("shift_jis")
        except UnicodeDecodeError:
            ch = ""

        idx = sjis_index(lead, trail)
        if idx is not None:
            if idx in self.sjis_metrics:
                return ch, self.sjis_metrics[idx]
            if idx in self.sjis_overlay:
                return ch, self.sjis_overlay[idx]

        rec = (trail - 0x40) if trail >= 0x40 else trail
        for page_key in (lead + 1, lead):
            page = self.page_tables.get(page_key)
            if page and rec in page:
                return ch, page[rec]

        return ch, None


def sjis_index(lead: int, trail: int) -> int | None:
    if 0x81 <= lead <= 0x9F:
        return (lead - 0x81) * 188 + (trail - 0x40)
    if 0xE0 <= lead <= 0xFC and trail >= 0x40:
        return (lead - 0xE0 + 31) * 188 + (trail - 0x40)
    return None


def parse_segments(data: bytes) -> list[bytes]:
    if len(data) < 8:
        return []
    count = struct.unpack_from("<I", data, 0)[0]
    if count > 10_000:
        return []
    segments: list[bytes] = []
    for i in range(count):
        off = struct.unpack_from("<I", data, 4 + i * 8)[0]
        end = struct.unpack_from("<I", data, 4 + (i + 1) * 8)[0] if i + 1 < count else len(data)
        if off < len(data) and end > off:
            segments.append(data[off:end])
    return segments


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


@lru_cache(maxsize=4)
def load_font(height: int = 18) -> tuple[bytes, int]:
    path = DPFONT / f"S{height}RM04P.DAT"
    data = path.read_bytes()
    return data, atlas_width(data, height)


@lru_cache(maxsize=1)
def _font18() -> tuple[bytes, int, int]:
    data, atlas_max = load_font(18)
    return data, atlas_max, 18


@lru_cache(maxsize=30_000)
def _cached_glyph_score(atlas_x: int, width: int = 18) -> int:
    font_data, _, font_height = _font18()
    return glyph_score(font_data, font_height, atlas_x, width)


def normalize_pl_name(name: str) -> str:
    name = name.upper()
    if name.endswith(".RLC") or name.endswith(".PAT") or name.endswith(".TLP"):
        return name
    if name.startswith("PL") or name.startswith("LM"):
        return f"{name}.RLC" if name.startswith("PL") else f"{name}.PAT"
    return name


def pl_index_to_name(index: int, mode1: dict[int, str]) -> str | None:
    raw = mode1.get(index)
    if raw is None:
        return None
    return normalize_pl_name(raw)


def iter_glyph_records(
    payload: bytes,
    segment_index: int,
    font_data: bytes,
    font_height: int,
    atlas_max: int,
) -> list[GlyphMetric]:
    if len(payload) < 6:
        return []
    page = struct.unpack_from("<H", payload, 4)[0]
    body = payload[6:]
    records: list[GlyphMetric] = []
    for ri in range(len(body) // GLYPH_RECORD_SIZE):
        rec = body[ri * GLYPH_RECORD_SIZE : (ri + 1) * GLYPH_RECORD_SIZE]
        width, height, atlas_x = struct.unpack_from("<HHH", rec, 0)
        if not (4 <= width <= 48 and atlas_x < atlas_max):
            continue
        if glyph_score(font_data, font_height, atlas_x, width) < MIN_GLYPH_SCORE:
            continue
        records.append(
            GlyphMetric(
                atlas_x=atlas_x,
                width=width,
                height=height,
                segment_index=segment_index,
                page=page,
                rec_index=ri,
            )
        )
    return records


def parse_cmd35_sjis_table(
    payload: bytes,
    font_data: bytes,
    font_height: int,
    atlas_max: int,
) -> dict[int, GlyphMetric]:
    if len(payload) < 10:
        return {}
    if struct.unpack_from("<I", payload, 0)[0] != CMD_SJIS_TABLE:
        return {}
    base = 6
    n = (len(payload) - base) // 2
    if n <= 0:
        return {}
    values = struct.unpack("<" + "H" * n, payload[base : base + n * 2])
    table: dict[int, GlyphMetric] = {}
    for idx, atlas_x in enumerate(values):
        if not (0 < atlas_x < atlas_max):
            continue
        width = 18
        if glyph_score(font_data, font_height, atlas_x, width) < MIN_GLYPH_SCORE:
            continue
        table[idx] = GlyphMetric(atlas_x, width, font_height, -1, 0, idx)
    return table


def _table_pairs(body: bytes, pos: int, count: int) -> list[tuple[int, int]]:
    return [struct.unpack_from("<HH", body, pos + 4 + j * 4) for j in range(count)]


def _table_quick_ok(pairs: list[tuple[int, int]], atlas_max: int) -> bool:
    ok = sum(1 for idx, val in pairs if idx < 7000 and 50 < val < atlas_max)
    slot = sum(
        1
        for idx, val in pairs
        if SLOT_BASE <= idx < SLOT_BASE + 512 and SLOT_BASE <= val < SLOT_BASE + 512
    )
    return ok >= max(4, len(pairs) // 3) or slot >= 2


def _classify_table_pairs(
    pairs: list[tuple[int, int]],
    atlas_max: int,
    font_height: int,
    slot_count: int,
) -> tuple[int, int, dict[int, GlyphMetric], dict[int, int]]:
    sjis_hits = 0
    slot_hits = 0
    sjis_overlay: dict[int, GlyphMetric] = {}
    slot_aliases: dict[int, int] = {}
    for idx, val in pairs:
        if idx < 7000 and 50 < val < atlas_max:
            if _cached_glyph_score(val) >= MIN_GLYPH_SCORE:
                sjis_hits += 1
                sjis_overlay[idx] = GlyphMetric(val, 18, font_height, -2, 0, idx)
        elif (
            SLOT_BASE <= idx < SLOT_BASE + slot_count
            and SLOT_BASE <= val < SLOT_BASE + slot_count
        ):
            slot_hits += 1
            slot_aliases[idx] = val
    return sjis_hits, slot_hits, sjis_overlay, slot_aliases


def parse_cmd26_tables(
    payload: bytes,
    atlas_max: int,
    font_height: int,
    slot_count: int,
) -> tuple[list[RuntimeTable], dict[int, GlyphMetric], dict[int, int]]:
    """
    Parse FUN_8c0191be ushort tables in cmd 26 bulk segments.

    Layout per table (Ghidra FUN_8c0191be / FUN_8c0193be):
      u16 hdr0, u16 hdr1 (count = low byte of hdr1)
      (u16 index, u16 value) * count
    """
    if len(payload) < 10 or struct.unpack_from("<I", payload, 0)[0] != CMD_RUNTIME_BULK:
        return [], {}, {}
    body = payload[6:]
    candidates: list[tuple[int, int, int, list[tuple[int, int]]]] = []
    for pos in range(0, len(body) - 8, 2):
        count = body[pos + 3]
        if not (4 <= count <= 128):
            continue
        end = pos + 4 + count * 4
        if end > len(body):
            continue
        pairs = _table_pairs(body, pos, count)
        if not _table_quick_ok(pairs, atlas_max):
            continue
        sjis_hits, slot_hits, _, _ = _classify_table_pairs(
            pairs, atlas_max, font_height, slot_count
        )
        score = sjis_hits + slot_hits
        if score >= max(4, count // 3):
            candidates.append((score, pos, end, pairs))

    candidates.sort(reverse=True)
    used: set[int] = set()
    tables: list[RuntimeTable] = []
    sjis_overlay: dict[int, GlyphMetric] = {}
    slot_aliases: dict[int, int] = {}

    for score, pos, end, pairs in candidates:
        if any(p in used for p in range(pos, end)):
            continue
        for p in range(pos, end):
            used.add(p)
        sjis_hits, slot_hits, ov, aliases = _classify_table_pairs(
            pairs, atlas_max, font_height, slot_count
        )
        tables.append(
            RuntimeTable(
                offset=pos,
                count=len(pairs),
                pairs=pairs,
                sjis_hits=sjis_hits,
                slot_hits=slot_hits,
            )
        )
        sjis_overlay.update(ov)
        slot_aliases.update(aliases)

    tables.sort(key=lambda t: t.offset)
    return tables, sjis_overlay, slot_aliases


def load_code_display(char_map_csv: Path, pl_file: str) -> dict[int, str]:
    display: dict[int, str] = {}
    with char_map_csv.open(encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            if row["pl_file"] != pl_file:
                continue
            for code_field, char_field in (
                ("char_a_code", "char_a"),
                ("char_b_code", "char_b"),
            ):
                code = int(row[code_field], 16)
                ch = row[char_field]
                if ch and not ch.startswith("U+"):
                    display[code] = ch
    return display


def build_runtime(pl_path: Path, char_map_csv: Path) -> PlRuntime:
    data = pl_path.read_bytes()
    pl_file = pl_path.name
    segments = parse_segments(data)
    font_data, atlas_max = load_font(18)
    font_height = 18

    linear: list[GlyphMetric] = []
    page_tables: dict[int, dict[int, GlyphMetric]] = {}
    sjis_metrics: dict[int, GlyphMetric] = {}
    code_aliases: dict[int, int] = {}
    cmd26_tables: list[RuntimeTable] = []
    sjis_overlay: dict[int, GlyphMetric] = {}

    for si, payload in enumerate(segments):
        if si == 0:
            continue
        if len(payload) < 4:
            continue
        cmd = struct.unpack_from("<I", payload, 0)[0]
        if cmd == CMD_SJIS_TABLE:
            sjis_metrics.update(parse_cmd35_sjis_table(payload, font_data, font_height, atlas_max))
        for glyph in iter_glyph_records(payload, si, font_data, font_height, atlas_max):
            linear.append(glyph)
            page_tables.setdefault(glyph.page, {})[glyph.rec_index] = glyph

    slots: dict[int, GlyphMetric] = {}
    for i, glyph in enumerate(linear):
        slots[SLOT_BASE + i] = glyph

    for payload in segments:
        if len(payload) >= 4 and struct.unpack_from("<I", payload, 0)[0] == CMD_RUNTIME_BULK:
            tables, overlay, aliases = parse_cmd26_tables(
                payload, atlas_max, font_height, len(linear)
            )
            cmd26_tables.extend(tables)
            for idx, metric in overlay.items():
                if idx not in sjis_metrics:
                    sjis_overlay[idx] = metric
            code_aliases.update(aliases)

    display = load_code_display(char_map_csv, pl_file)
    for code, ch in list(display.items()):
        if 0xC000 <= code <= 0xC0FF:
            alias = SLOT_BASE + (code & 0xFF)
            if alias in slots:
                slots.setdefault(code, slots[alias])
                display.setdefault(alias, ch)

    return PlRuntime(
        pl_file=pl_file,
        slots=slots,
        code_display=display,
        code_aliases=code_aliases,
        sjis_metrics=sjis_metrics,
        page_tables=page_tables,
        cmd26_tables=cmd26_tables,
        sjis_overlay=sjis_overlay,
    )


@dataclass
class SceneContext:
    """Multi-PL runtime for one dialogue bytecode stream."""

    pl_files: list[str]
    active: str
    char_map_csv: str
    runtimes: dict[str, PlRuntime]
    key_maps: dict[str, dict[int, int]]
    switches: int = 0

    def lookup_key(self, key: int) -> tuple[str | None, int | None]:
        kmap = self.key_maps.get(self.active)
        if kmap and key in kmap:
            return self.active, kmap[key]
        return None, None

    def _runtime(self, pl_file: str) -> PlRuntime | None:
        if pl_file in self.runtimes:
            return self.runtimes[pl_file]
        if resolve_pl_path(pl_file):
            self.runtimes[pl_file] = get_runtime(pl_file, self.char_map_csv)
            return self.runtimes[pl_file]
        return None

    def resolve_sjis(self, lead: int, trail: int) -> tuple[str, GlyphMetric | None, str]:
        order: list[str] = [self.active]
        for pf in self.pl_files:
            if pf not in order:
                order.append(pf)
        for pf in SJIS_FALLBACK_PLS:
            if pf not in order:
                order.append(pf)
        for pf in order:
            rt = self._runtime(pf)
            if rt is None:
                continue
            ch, glyph = rt.resolve_sjis(lead, trail)
            if glyph is not None:
                return ch, glyph, pf
        rt = self._runtime(self.active) or next(iter(self.runtimes.values()))
        ch, glyph = rt.resolve_sjis(lead, trail)
        return ch, glyph, rt.pl_file

    def resolve_code(self, pl_file: str, code: int) -> tuple[str, GlyphMetric | None]:
        rt = self.runtimes.get(pl_file)
        if rt is None:
            rt = next(iter(self.runtimes.values()))
        return rt.resolve_code(code)

    def switch(self, pl_file: str) -> bool:
        if pl_file in self.runtimes and pl_file != self.active:
            self.active = pl_file
            self.switches += 1
            return True
        if pl_file in self.runtimes:
            return False
        return False


def build_scene_context(
    body: bytes,
    mode1: dict[int, str],
    char_maps: dict[str, dict[int, int]],
    char_map_csv: Path,
) -> SceneContext:
    refs: list[str] = []
    seen: set[str] = set()

    def add_index(index: int) -> None:
        name = pl_index_to_name(index, mode1)
        if name is None or not name.startswith("PL"):
            return
        if name not in seen and resolve_pl_path(name):
            seen.add(name)
            refs.append(name)

    if len(body) >= 2:
        add_index(struct.unpack_from("<H", body, 0)[0])

    for pos in range(len(body) - 3):
        if body[pos : pos + 3] == b"\x1f\x00\x80":
            add_index(body[pos + 3])

    hit_rank: list[tuple[int, str]] = []
    for pf, kmap in char_maps.items():
        if not pf.startswith("PL"):
            continue
        hits = sum(
            1
            for pos in range(0, min(len(body), 512) - 1, 2)
            if struct.unpack_from("<H", body, pos)[0] in kmap
        )
        if hits:
            hit_rank.append((hits, pf))
    hit_rank.sort(reverse=True)
    for _, pf in hit_rank[:4]:
        if pf not in seen and resolve_pl_path(pf):
            seen.add(pf)
            refs.append(pf)

    if not refs:
        refs = ["PL00.RLC"]

    runtimes: dict[str, PlRuntime] = {}
    key_maps: dict[str, dict[int, int]] = {}
    csv_str = str(char_map_csv)
    for pf in refs:
        if resolve_pl_path(pf):
            runtimes[pf] = get_runtime(pf, csv_str)
            key_maps[pf] = char_maps.get(pf, {})

    active = refs[0]
    if hit_rank and active not in {hit_rank[0][1]}:
        active = hit_rank[0][1]
    if active not in runtimes and runtimes:
        active = next(iter(runtimes))

    return SceneContext(
        pl_files=refs,
        active=active,
        char_map_csv=csv_str,
        runtimes=runtimes,
        key_maps=key_maps,
    )


def resolve_pl_path(pl_file: str) -> Path | None:
    for name in (pl_file, pl_file.upper(), pl_file.lower()):
        path = COMN / name
        if path.exists():
            return path
    return None


@lru_cache(maxsize=64)
def get_runtime(pl_file: str, char_map_csv: str) -> PlRuntime:
    path = resolve_pl_path(pl_file)
    if path is None:
        path = resolve_pl_path("PL00.RLC")
    if path is None:
        raise FileNotFoundError(f"No PL runtime file for {pl_file}")
    return build_runtime(path, Path(char_map_csv))


def export_runtime_csv(out_csv: Path, char_map_csv: Path) -> int:
    rows: list[dict] = []
    for pl_path in sorted(COMN.glob("PL*.RLC")):
        rt = build_runtime(pl_path, char_map_csv)
        for code, glyph in sorted(rt.slots.items()):
            rows.append(
                {
                    "pl_file": rt.pl_file,
                    "slot_code": f"0x{code:04X}",
                    "atlas_x": glyph.atlas_x,
                    "width": glyph.width,
                    "height": glyph.height,
                    "page": f"0x{glyph.page:04X}",
                    "rec_index": glyph.rec_index,
                    "segment_index": glyph.segment_index,
                    "display": rt.code_display.get(code, ""),
                }
            )
        for idx, metric in sorted(rt.sjis_metrics.items()):
            rows.append(
                {
                    "pl_file": rt.pl_file,
                    "slot_code": f"sjis_idx:{idx}",
                    "atlas_x": metric.atlas_x,
                    "width": "",
                    "height": "",
                    "page": "",
                    "rec_index": "",
                    "segment_index": "cmd35",
                    "display": "",
                }
            )
        for idx, metric in sorted(rt.sjis_overlay.items()):
            rows.append(
                {
                    "pl_file": rt.pl_file,
                    "slot_code": f"sjis_idx:{idx}",
                    "atlas_x": metric.atlas_x,
                    "width": metric.width,
                    "height": metric.height,
                    "page": "",
                    "rec_index": "",
                    "segment_index": "cmd26",
                    "display": "",
                }
            )

    out_csv.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "pl_file",
        "slot_code",
        "display",
        "atlas_x",
        "width",
        "height",
        "page",
        "rec_index",
        "segment_index",
    ]
    with out_csv.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    return len(rows)


def export_cmd26_csv(out_csv: Path, char_map_csv: Path) -> int:
    rows: list[dict] = []
    for pl_path in sorted(COMN.glob("PL*.RLC")):
        rt = build_runtime(pl_path, char_map_csv)
        for ti, table in enumerate(rt.cmd26_tables):
            for pair_i, (idx, val) in enumerate(table.pairs):
                rows.append(
                    {
                        "pl_file": rt.pl_file,
                        "table_index": ti,
                        "table_offset": table.offset,
                        "pair_index": pair_i,
                        "index": idx,
                        "value": val,
                        "index_hex": f"0x{idx:04X}",
                        "value_hex": f"0x{val:04X}",
                        "sjis_hits": table.sjis_hits,
                        "slot_hits": table.slot_hits,
                    }
                )
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    fields = [
        "pl_file",
        "table_index",
        "table_offset",
        "pair_index",
        "index",
        "value",
        "index_hex",
        "value_hex",
        "sjis_hits",
        "slot_hits",
    ]
    with out_csv.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    return len(rows)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "-o",
        "--csv",
        type=Path,
        default=ROOT / "output" / "pl_runtime_slots.csv",
    )
    parser.add_argument(
        "--char-map",
        type=Path,
        default=ROOT / "output" / "pl_char_maps.csv",
    )
    parser.add_argument(
        "--cmd26-csv",
        type=Path,
        default=ROOT / "output" / "pl_cmd26_tables.csv",
    )
    args = parser.parse_args()
    n = export_runtime_csv(args.csv, args.char_map)
    n26 = export_cmd26_csv(args.cmd26_csv, args.char_map)
    print(f"Wrote {n} runtime slot rows -> {args.csv}")
    print(f"Wrote {n26} cmd26 pair rows -> {args.cmd26_csv}")
