from __future__ import annotations
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from .models import ScanResult
from .pe import PEImage

def _hex(v):
    return None if v is None else f"0x{v:X}"

def export_json(path: str | Path, image: PEImage, results: list[ScanResult], signature_meta: dict | None = None) -> None:
    payload = {
        "generatedUtc": datetime.now(timezone.utc).isoformat(),
        "inputFile": image.path.name,
        "sha256": image.sha256,
        "peTimestamp": image.timestamp,
        "imageBase": _hex(image.image_base),
        "signatureMeta": signature_meta or {},
        "results": [
            {
                "name": r.name,
                "status": r.status,
                "rva": _hex(r.resolved_rva),
                "previousRva": _hex(r.previous_rva),
                "delta": None if r.delta is None else (f"+0x{r.delta:X}" if r.delta >= 0 else f"-0x{-r.delta:X}"),
                "matchCount": r.match_count,
                "matchRvas": [_hex(x) for x in r.match_rvas],
                "section": r.section,
                "notes": r.notes,
                "error": r.error,
            }
            for r in results
        ],
    }
    Path(path).write_text(json.dumps(payload, indent=2), encoding="utf-8")

def _cpp_name(name: str) -> str:
    s = re.sub(r"[^A-Za-z0-9_]", "_", name)
    if not s or s[0].isdigit():
        s = "offset_" + s
    return s

def export_cpp(path: str | Path, results: list[ScanResult]) -> None:
    lines = ["#pragma once", "#include <cstdint>", "", "namespace bo6_offsets {", ""]
    for r in results:
        if r.resolved_rva is not None:
            lines.append(f"inline constexpr std::uintptr_t {_cpp_name(r.name)} = 0x{r.resolved_rva:X};")
    lines += ["", "} // namespace bo6_offsets", ""]
    Path(path).write_text("\n".join(lines), encoding="utf-8")
