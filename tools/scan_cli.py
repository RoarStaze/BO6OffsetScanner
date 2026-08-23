#!/usr/bin/env python3
from __future__ import annotations
import argparse
import sys
from pathlib import Path

# Allow `python tools/scan_cli.py ...` from a source checkout without installation.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from bo6scanner.pe import PEImage
from bo6scanner.signatures import load_signatures
from bo6scanner.scanner import scan_all
from bo6scanner.exporters import export_json, export_cpp

def main():
    p = argparse.ArgumentParser(description="Offline PE signature scanner")
    p.add_argument("pe")
    p.add_argument("signatures")
    p.add_argument("--json")
    p.add_argument("--cpp")
    args = p.parse_args()
    image = PEImage(args.pe)
    meta, sigs = load_signatures(args.signatures)
    results = scan_all(image, sigs)
    for r in results:
        value = "-" if r.resolved_rva is None else f"0x{r.resolved_rva:X}"
        print(f"{r.status:10} {r.name:36} {value:>12} matches={r.match_count}")
    if args.json: export_json(args.json, image, results, meta)
    if args.cpp: export_cpp(args.cpp, results)

if __name__ == "__main__":
    main()
