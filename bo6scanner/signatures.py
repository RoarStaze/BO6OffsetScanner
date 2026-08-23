from __future__ import annotations
import json
from pathlib import Path
from .models import Resolver, Signature

class SignatureFormatError(ValueError):
    pass

def _parse_int(value):
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    raise SignatureFormatError(f"Expected integer or integer string, got {type(value).__name__}")

def load_signatures(path: str | Path) -> tuple[dict, list[Signature]]:
    obj = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(obj, dict) or not isinstance(obj.get("signatures"), list):
        raise SignatureFormatError("Root object must contain a signatures array.")
    out: list[Signature] = []
    seen: set[str] = set()
    for item in obj["signatures"]:
        if not isinstance(item, dict):
            raise SignatureFormatError("Each signature must be an object.")
        name = str(item.get("name", "")).strip()
        pattern = str(item.get("pattern", "")).strip()
        if not name or not pattern:
            raise SignatureFormatError("Each signature requires name and pattern.")
        if name in seen:
            raise SignatureFormatError(f"Duplicate signature name: {name}")
        seen.add(name)
        r = item.get("resolver") or {"kind": "match"}
        resolver = Resolver(
            kind=str(r.get("kind", "match")),
            addend=_parse_int(r.get("addend", 0)) or 0,
            displacement_offset=_parse_int(r.get("displacementOffset", 0)) or 0,
            next_instruction_offset=_parse_int(r.get("nextInstructionOffset", 0)) or 0,
        )
        out.append(Signature(
            name=name,
            pattern=pattern,
            section=item.get("section"),
            expected_matches=int(item.get("expectedMatches", 1)),
            previous_rva=_parse_int(item.get("previousRva")),
            resolver=resolver,
            notes=str(item.get("notes", "")),
        ))
    meta = {k: v for k, v in obj.items() if k != "signatures"}
    return meta, out
