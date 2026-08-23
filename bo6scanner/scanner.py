from __future__ import annotations
import struct
from .models import Signature, ScanResult
from .pe import PEImage

class PatternError(ValueError):
    pass

def compile_pattern(pattern: str) -> tuple[list[int], list[bool]]:
    values: list[int] = []
    fixed: list[bool] = []
    for token in pattern.replace("\t", " ").split():
        if token in {"?", "??"}:
            values.append(0)
            fixed.append(False)
        else:
            if len(token) != 2:
                raise PatternError(f"Invalid token {token!r}; use hex bytes or ??.")
            try:
                values.append(int(token, 16))
                fixed.append(True)
            except ValueError as exc:
                raise PatternError(f"Invalid hex byte {token!r}.") from exc
    if not values:
        raise PatternError("Pattern is empty.")
    return values, fixed

def find_all(buf: bytes, pattern: str) -> list[int]:
    values, fixed = compile_pattern(pattern)
    n = len(values)
    if n > len(buf):
        return []
    anchor = next((i for i, is_fixed in enumerate(fixed) if is_fixed), None)
    if anchor is None:
        return list(range(0, len(buf) - n + 1))
    needle = values[anchor]
    results: list[int] = []
    start = 0
    while True:
        pos = buf.find(bytes([needle]), start)
        if pos < 0:
            break
        base = pos - anchor
        if 0 <= base <= len(buf) - n:
            ok = True
            for i in range(n):
                if fixed[i] and buf[base+i] != values[i]:
                    ok = False
                    break
            if ok:
                results.append(base)
        start = pos + 1
    return results

def _resolve(image: PEImage, sig: Signature, match_rva: int) -> int:
    r = sig.resolver
    kind = r.kind.lower()
    if kind == "match":
        return match_rva + r.addend
    if kind in {"rel32", "relative32", "riprel32"}:
        disp_rva = match_rva + r.displacement_offset
        disp_off = image.rva_to_file_offset(disp_rva)
        if disp_off + 4 > len(image.data):
            raise ValueError("rel32 displacement extends past end of file")
        disp = struct.unpack_from("<i", image.data, disp_off)[0]
        return match_rva + r.next_instruction_offset + disp + r.addend
    raise ValueError(f"Unsupported resolver kind: {r.kind}")

def scan_signature(image: PEImage, sig: Signature) -> ScanResult:
    matches: list[int] = []
    try:
        for section, base_file_off, chunk in image.scan_ranges(sig.section):
            for local_off in find_all(chunk, sig.pattern):
                matches.append(image.file_offset_to_rva(base_file_off + local_off))
        if not matches:
            status = "missing"
            resolved = None
            error = None
        elif sig.expected_matches > 0 and len(matches) != sig.expected_matches:
            status = "ambiguous"
            resolved = None
            error = f"expected {sig.expected_matches} match(es), found {len(matches)}"
        else:
            resolved = _resolve(image, sig, matches[0])
            status = "resolved"
            error = None
        delta = None if resolved is None or sig.previous_rva is None else resolved - sig.previous_rva
        return ScanResult(sig.name, status, len(matches), matches, resolved, sig.previous_rva, delta, sig.section, sig.notes, error)
    except Exception as exc:
        return ScanResult(sig.name, "error", len(matches), matches, None, sig.previous_rva, None, sig.section, sig.notes, str(exc))

def scan_all(image: PEImage, signatures: list[Signature]) -> list[ScanResult]:
    return [scan_signature(image, s) for s in signatures]
