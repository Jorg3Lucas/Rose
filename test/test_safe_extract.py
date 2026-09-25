import tempfile
import unittest
import zipfile
from pathlib import Path

from utils.core.safe_extract import (
    UnsafePathError,
    is_safe_path,
    safe_extract,
    safe_extractall,
    safe_extractall_from_bytes,
)


def make_zip(path, members):
    """Build a ZIP with the given {name: content} entries."""
    with zipfile.ZipFile(path, 'w') as zf:
        for name, content in members.items():
            zf.writestr(name, content)
    return path


def make_zip_bytes(members):
    import io
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as zf:
        for name, content in members.items():
            zf.writestr(name, content)
    return buffer.getvalue()


class IsSafePathTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.root = Path(self.temp_dir.name)

    def test_a_file_nested_under_the_base_is_safe(self):
        base = self.root / 'mods'
        self.assertTrue(is_safe_path(base, base / 'champion' / 'skin' / 'file.bin'))

    def test_the_base_itself_is_safe(self):
        base = self.root / 'mods'
        self.assertTrue(is_safe_path(base, base))

    def test_a_plain_parent_traversal_is_rejected(self):
        base = self.root / 'mods'
        self.assertFalse(is_safe_path(base, base / '..' / '..' / 'Windows' / 'evil.txt'))

    def test_a_sibling_sharing_the_base_prefix_is_rejected(self):
        # '<root>/mods/../mods-evil/x' escapes while still starting with '<root>/mods'
        base = self.root / 'mods'
        self.assertFalse(is_safe_path(base, base / '..' / 'mods-evil' / 'x.txt'))

    def test_an_absolute_path_outside_the_base_is_rejected(self):
        base = self.root / 'mods'
        outside = self.root / 'elsewhere' / 'x.txt'
        self.assertFalse(is_safe_path(base, outside))


class SafeExtractTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.root = Path(self.temp_dir.name)
        self.dest = self.root / 'dest'

    def test_a_normal_archive_is_extracted(self):
        archive = make_zip(self.root / 'ok.zip', {
            'META/info.json': '{}',
            'WAD/Zed.wad.client': 'binary',
        })
        safe_extractall(archive, self.dest)
        self.assertTrue((self.dest / 'META' / 'info.json').exists())
        self.assertTrue((self.dest / 'WAD' / 'Zed.wad.client').exists())

    def test_a_traversing_archive_is_rejected_before_writing_anything(self):
        archive = make_zip(self.root / 'evil.zip', {
            'META/info.json': '{}',
            '../escaped.txt': 'pwned',
        })
        with self.assertRaises(UnsafePathError):
            safe_extractall(archive, self.dest)
        self.assertFalse((self.root / 'escaped.txt').exists())
        self.assertFalse((self.dest / 'META' / 'info.json').exists())

    def test_a_sibling_prefix_traversal_is_rejected(self):
        archive = make_zip(self.root / 'evil.zip', {
            '../dest-evil/escaped.txt': 'pwned',
        })
        with self.assertRaises(UnsafePathError):
            safe_extractall(archive, self.dest)
        self.assertFalse((self.root / 'dest-evil' / 'escaped.txt').exists())

    def test_an_absolute_entry_is_rejected(self):
        archive = make_zip(self.root / 'evil.zip', {'/abs.txt': 'pwned'})
        with self.assertRaises(UnsafePathError):
            safe_extractall(archive, self.dest)

    def test_in_memory_archives_are_validated_too(self):
        with self.assertRaises(UnsafePathError):
            safe_extractall_from_bytes(
                make_zip_bytes({'../escaped.txt': 'pwned'}), self.dest)
        self.assertFalse((self.root / 'escaped.txt').exists())

    def test_single_member_extraction_is_validated(self):
        archive = make_zip(self.root / 'evil.zip', {'../escaped.txt': 'pwned'})
        with self.assertRaises(UnsafePathError):
            safe_extract(archive, '../escaped.txt', self.dest)

    def test_single_member_extraction_returns_the_created_path(self):
        archive = make_zip(self.root / 'ok.zip', {'META/info.json': '{}'})
        written = safe_extract(archive, 'META/info.json', self.dest)
        self.assertEqual(written.resolve(), (self.dest / 'META' / 'info.json').resolve())
        self.assertTrue(written.exists())


if __name__ == '__main__':
    unittest.main()
