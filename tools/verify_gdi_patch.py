#!/usr/bin/env python3
"""Verify test GDIs differ from retail and from each other (SELOBJ + IP.BIN title)."""

from __future__ import annotations

import hashlib
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import iso_patch as ip
from selobj_menu import parse_rlc, segment_body
from selobj_patch import IP_TITLE_ORIG, SELOBJ_EXTENT, gdi_descriptor_for_label, ip_title_for_label

RETAIL_GDI = ROOT / "[GDI] Eldorado Gate - Volume 1 (Japan)" / "Eldorado Gate - Volume 1 (Japan)"
TESTS = [
    ("retail", RETAIL_GDI, None),
    ("swap-continue", ROOT / "output" / "gdi_swap_test", "swap-continue"),
    ("new-game-en", ROOT / "output" / "gdi_newgame_test", "new-game-en"),
    ("nuclear", ROOT / "output" / "gdi_nuclear_test", "nuclear"),
]


def md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def read_selobj_from_gdi(folder: Path) -> bytes | None:
    track3 = folder / "track03.bin"
    if not track3.exists():
        return None
    retail = ROOT / "disc_extracted" / "COMN" / "SELOBJ.RLC"
    size = len(retail.read_bytes())
    return ip.read_extent_track3(track3.read_bytes(), SELOBJ_EXTENT, size)


def read_ip_title(folder: Path) -> str | None:
    track1 = folder / "track01.bin"
    if not track1.exists():
        return None
    data = track1.read_bytes()
    pos = data.find(IP_TITLE_ORIG)
    if pos < 0:
        pos = 0x90 if len(data) > 0xA0 else 0
    return data[pos : pos + 16].decode("ascii", errors="replace").strip()


def main() -> None:
    print("=== Vérification des GDI de test ===\n")
    fingerprints: dict[str, str] = {}

    for name, folder, label in TESTS:
        if not folder.exists():
            print(f"[{name}] MANQUANT: {folder}")
            continue
        gdi_files = list(folder.glob("*.gdi"))
        gdi_name = gdi_files[0].name if gdi_files else "(pas de .gdi)"
        selobj = read_selobj_from_gdi(folder)
        title = read_ip_title(folder)
        if label:
            expect_title = ip_title_for_label(label).decode().strip()
            expect_gdi = gdi_descriptor_for_label(label)
        else:
            expect_title = "ELDORADO GATE VOL1"
            expect_gdi = "(retail)"

        seg1_head = ""
        if selobj:
            fp = md5(selobj)
            fingerprints[name] = fp
            try:
                body = segment_body(parse_rlc(selobj)[1])
                seg1_head = body[:24].hex()
            except (struct.error, IndexError, ValueError):
                seg1_head = selobj[:24].hex() + " (corrupt/nuclear)"
        else:
            fp = "n/a"

        print(f"[{name}]")
        print(f"  dossier : {folder}")
        print(f"  .gdi    : {gdi_name}")
        if label:
            print(f"  attendu : {expect_gdi}")
        print(f"  IP title: {title!r}" + (f" (attendu {expect_title!r})" if label else ""))
        print(f"  SELOBJ  : md5={fp}")
        if seg1_head:
            print(f"  seg1    : {seg1_head}")
        print()

    retail_fp = fingerprints.get("retail")
    for name, fp in fingerprints.items():
        if name == "retail":
            continue
        if retail_fp and fp == retail_fp:
            print(f"!! {name} = IDENTIQUE au retail (patch non appliqué)")
        elif fp in fingerprints.values() and sum(1 for v in fingerprints.values() if v == fp) > 1:
            print(f"!! {name} = doublon avec un autre build")
        else:
            print(f"OK {name} diffère du retail")

    print("\nDans Flycast, le titre disque doit afficher « EDG TEST … » pour les builds patchés.")
    print("Si le titre reste « ELDORADO GATE VOL1 », ce n'est pas le bon GDI.")


if __name__ == "__main__":
    main()
