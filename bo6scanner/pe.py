from __future__ import annotations
import hashlib
import struct
from pathlib import Path
from .models import Section

class PEFormatError(ValueError):
    pass

class PEImage:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.data = self.path.read_bytes()
        self.sections: list[Section] = []
        self.image_base = 0
        self.timestamp = 0
        self.machine = 0
        self._parse()

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.data).hexdigest()

    def _parse(self) -> None:
        d = self.data
        if len(d) < 0x40 or d[:2] != b"MZ":
            raise PEFormatError("Not a valid PE file (missing MZ header).")
        e_lfanew = struct.unpack_from("<I", d, 0x3C)[0]
        if e_lfanew + 0x18 > len(d) or d[e_lfanew:e_lfanew+4] != b"PE\0\0":
            raise PEFormatError("Not a valid PE file (missing PE signature).")
        file_hdr = e_lfanew + 4
        self.machine, number_of_sections, self.timestamp = struct.unpack_from("<HHI", d, file_hdr)
        size_optional_header = struct.unpack_from("<H", d, file_hdr + 16)[0]
        opt = file_hdr + 20
        if opt + size_optional_header > len(d):
            raise PEFormatError("Truncated optional header.")
        magic = struct.unpack_from("<H", d, opt)[0]
        if magic == 0x20B:
            self.image_base = struct.unpack_from("<Q", d, opt + 24)[0]
        elif magic == 0x10B:
            self.image_base = struct.unpack_from("<I", d, opt + 28)[0]
        else:
            raise PEFormatError(f"Unsupported optional-header magic: 0x{magic:X}")
        sec_off = opt + size_optional_header
        for i in range(number_of_sections):
            off = sec_off + i * 40
            if off + 40 > len(d):
                raise PEFormatError("Truncated section table.")
            raw_name = d[off:off+8].split(b"\0", 1)[0]
            name = raw_name.decode("ascii", errors="replace")
            virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from("<IIII", d, off + 8)
            characteristics = struct.unpack_from("<I", d, off + 36)[0]
            self.sections.append(Section(name, virtual_address, virtual_size, raw_offset, raw_size, characteristics))

    def section(self, name: str) -> Section | None:
        target = name.strip().lower()
        return next((s for s in self.sections if s.name.lower() == target), None)

    def file_offset_to_rva(self, file_offset: int) -> int:
        for s in self.sections:
            if s.raw_offset <= file_offset < s.raw_offset + s.raw_size:
                return s.virtual_address + (file_offset - s.raw_offset)
        return file_offset

    def rva_to_file_offset(self, rva: int) -> int:
        for s in self.sections:
            span = max(s.virtual_size, s.raw_size)
            if s.virtual_address <= rva < s.virtual_address + span:
                return s.raw_offset + (rva - s.virtual_address)
        if 0 <= rva < len(self.data):
            return rva
        raise PEFormatError(f"RVA 0x{rva:X} is outside mapped sections.")

    def scan_ranges(self, section_name: str | None = None) -> list[tuple[Section | None, int, bytes]]:
        if section_name:
            s = self.section(section_name)
            if not s:
                raise PEFormatError(f"Section {section_name!r} was not found.")
            return [(s, s.raw_offset, self.data[s.raw_offset:s.raw_offset+s.raw_size])]
        ranges: list[tuple[Section | None, int, bytes]] = []
        for s in self.sections:
            if s.raw_size:
                ranges.append((s, s.raw_offset, self.data[s.raw_offset:s.raw_offset+s.raw_size]))
        return ranges
