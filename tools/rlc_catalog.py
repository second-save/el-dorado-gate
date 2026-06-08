#!/usr/bin/env python3
"""Build a catalog of RLC script files (segments, sizes, encoding hints)."""

from __future__ import annotations

import argparse
import csv
import re
import struct
from pathlib import Path

from rlc_parse import parse_rlc, sjis_guess


def kanji_run(text: str) -> str:
    chars = re.findall(r"[\u4e00-\u9fff\u3040-\u30ff]", text)
    return "".join(chars)


def catalog_file(path: Path) -> list[dict]:
    data = path.read_bytes()
    segments = parse_rlc(data)
    rows: list[dict] = []
    for seg in segments:
        guess, note = sjis_guess(seg.payload)
        rows.append(
            {
                "source_file": str(path),
                "category": _category(path),
                "segment_index": seg.index,
                "segment_offset": f"0x{seg.offset:X}",
                "segment_size": seg.size,
                "meta_field": f"0x{seg.meta:X}",
                "encoding_note": note,
                "kanji_preview": kanji_run(guess)[:120],
                "text_preview": guess[:200].replace("\n", "\\n"),
            }
        )
    return rows


def _category(path: Path) -> str:
    name = path.name.upper()
    parent = path.parent.name.upper()
    if name.startswith("F") and name.endswith(".RLC"):
        return "scene_script"
    if name.startswith("PL"):
        return "player_dialogue"
    if name.startswith("EN_OBJ"):
        return "enemy_object_names"
    if parent.startswith("SCEN"):
        return "scene_asset"
    if parent == "COMN":
        return "common"
    return "other"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("-o", "--csv", type=Path, default=Path("output/rlc_catalog.csv"))
    args = parser.parse_args()

    paths = sorted(args.input.rglob("*.RLC"))
    rows: list[dict] = []
    for path in paths:
        rows.extend(catalog_file(path))

    args.csv.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        raise SystemExit("No RLC files found")

    with args.csv.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    print(f"Cataloged {len(rows)} segments from {len(paths)} RLC files -> {args.csv}")


if __name__ == "__main__":
    main()
