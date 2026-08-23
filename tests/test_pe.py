import struct
import tempfile
import unittest
from pathlib import Path
from bo6scanner.pe import PEImage

def minimal_pe() -> bytes:
    d = bytearray(0x600)
    d[0:2] = b"MZ"
    struct.pack_into("<I", d, 0x3C, 0x80)
    d[0x80:0x84] = b"PE\0\0"
    fh = 0x84
    struct.pack_into("<HHI", d, fh, 0x8664, 1, 0x12345678)
    struct.pack_into("<H", d, fh + 16, 0xF0)
    opt = fh + 20
    struct.pack_into("<H", d, opt, 0x20B)
    struct.pack_into("<Q", d, opt + 24, 0x140000000)
    sec = opt + 0xF0
    d[sec:sec+8] = b".text\0\0\0"
    struct.pack_into("<IIII", d, sec + 8, 0x200, 0x1000, 0x200, 0x400)
    struct.pack_into("<I", d, sec + 36, 0x60000020)
    d[0x410:0x414] = bytes.fromhex("DE AD BE EF")
    return bytes(d)

class PETests(unittest.TestCase):
    def test_mapping(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "x.exe"
            p.write_bytes(minimal_pe())
            image = PEImage(p)
            self.assertEqual(image.file_offset_to_rva(0x410), 0x1010)
            self.assertEqual(image.rva_to_file_offset(0x1010), 0x410)
            self.assertEqual(image.image_base, 0x140000000)

if __name__ == "__main__":
    unittest.main()
