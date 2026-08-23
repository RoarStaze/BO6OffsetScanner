from __future__ import annotations
from dataclasses import dataclass
from typing import Optional

@dataclass(frozen=True)
class Section:
    name: str
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    characteristics: int

@dataclass(frozen=True)
class Resolver:
    kind: str = "match"
    addend: int = 0
    displacement_offset: int = 0
    next_instruction_offset: int = 0

@dataclass(frozen=True)
class Signature:
    name: str
    pattern: str
    section: Optional[str] = None
    expected_matches: int = 1
    previous_rva: Optional[int] = None
    resolver: Resolver = Resolver()
    notes: str = ""

@dataclass
class ScanResult:
    name: str
    status: str
    match_count: int
    match_rvas: list[int]
    resolved_rva: Optional[int]
    previous_rva: Optional[int]
    delta: Optional[int]
    section: Optional[str]
    notes: str = ""
    error: Optional[str] = None
