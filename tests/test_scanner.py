import unittest
from bo6scanner.scanner import compile_pattern, find_all

class PatternTests(unittest.TestCase):
    def test_compile(self):
        values, fixed = compile_pattern("48 8B ?? ? 90")
        self.assertEqual(values, [0x48, 0x8B, 0, 0, 0x90])
        self.assertEqual(fixed, [True, True, False, False, True])

    def test_find_all(self):
        buf = bytes.fromhex("00 48 8B 01 90 48 8B FF 90")
        self.assertEqual(find_all(buf, "48 8B ?? 90"), [1, 5])

if __name__ == "__main__":
    unittest.main()
