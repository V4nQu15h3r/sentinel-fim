"""
tests/test_fim.py

Unit tests for SentinelFIM's core hashing logic.

These tests use Python's built-in `unittest` framework and `tempfile`
module so they run cleanly on any machine (Windows, macOS, Linux)
without leaving junk files behind.

Run from the repository root with:
    python -m unittest discover -s tests -v
"""

import sys
import unittest
import tempfile
from pathlib import Path

# --- Make sure "src/" is importable no matter where this test is run from ---
# This inserts the project's src/ folder onto Python's module search path,
# so `import sentinel` works whether you run this file directly or via
# `python -m unittest discover`.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = PROJECT_ROOT / "src"
sys.path.insert(0, str(SRC_DIR))

from sentinel import hash_file  # noqa: E402  (import after sys.path tweak, intentional)


class TestHashFile(unittest.TestCase):
    """Tests for sentinel.hash_file() - the SHA-256 fingerprinting function
    that all of SentinelFIM's integrity checks depend on."""

    def setUp(self):
        """Runs before every test: creates a fresh temporary file on disk
        that each test can freely write to and hash."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_file_path = Path(self.temp_dir.name) / "sample.txt"

    def tearDown(self):
        """Runs after every test: cleans up the temporary directory and
        everything inside it."""
        self.temp_dir.cleanup()

    def _write(self, content: str):
        """Small helper: overwrites the temp file with the given text."""
        self.temp_file_path.write_text(content, encoding="utf-8")

    def test_hash_is_deterministic(self):
        """Hashing the exact same content twice must produce the exact
        same fingerprint - hashing should never be random."""
        self._write("Integrity is the 'I' in the CIA Triad.")
        first_hash = hash_file(self.temp_file_path)
        second_hash = hash_file(self.temp_file_path)
        self.assertEqual(first_hash, second_hash)

    def test_hash_changes_when_content_changes(self):
        """This is the core integrity guarantee SentinelFIM relies on:
        if a file's content changes at all, its hash must change too."""
        # 1. Write the original data and capture its fingerprint.
        self._write("original, untampered content")
        original_hash = hash_file(self.temp_file_path)

        # 2. Simulate tampering by overwriting the file with new content.
        self._write("this content has been modified by an attacker")
        modified_hash = hash_file(self.temp_file_path)

        # 3. The fingerprints must differ, proving the tampering is detectable.
        self.assertNotEqual(original_hash, modified_hash)

    def test_hash_is_valid_sha256_hex_digest(self):
        """A SHA-256 hash, written as hexadecimal text, is always exactly
        64 characters long and contains only hex digits (0-9, a-f)."""
        self._write("some content")
        digest = hash_file(self.temp_file_path)
        self.assertEqual(len(digest), 64)
        self.assertTrue(all(c in "0123456789abcdef" for c in digest))

    def test_large_file_is_hashed_in_chunks_without_error(self):
        """Confirms the chunked reading approach works correctly on a file
        larger than a single 4096-byte chunk, so we know it will scale
        safely to much bigger files (e.g. multi-gigabyte logs) too."""
        # Write ~50,000 bytes - more than 12x the 4096-byte chunk size.
        large_content = "A" * 50_000
        self._write(large_content)

        digest = hash_file(self.temp_file_path)
        self.assertEqual(len(digest), 64)


if __name__ == "__main__":
    unittest.main()
