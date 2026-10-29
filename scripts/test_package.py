#!/usr/bin/env python3
"""Exercise archive guards with synthetic tools and files, not native code."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile

PACKAGER = Path(__file__).resolve().with_name('package.py')

class PackageChecks(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='package-test-')
        self.root = Path(self.tmp.name)
        (self.root / 'node_modules/libpq/build/Release').mkdir(parents=True)
        (self.root / 'node_modules/libpq/build/Release/addon.node').write_bytes(b'synthetic addon')
        (self.root / 'pg/lib').mkdir(parents=True)
        (self.root / 'pg/lib/libpq.so.5').write_bytes(b'synthetic libpq')
        (self.root / 'COPYRIGHT').write_text('synthetic license')
        tools = self.root / 'tools'
        tools.mkdir()
        scripts = {
            'readelf': '#!/bin/sh\nif [ "$1" = -h ]; then echo "Machine: AArch64"; else echo GLIBC_2.39; fi\n',
            'strip': '#!/bin/sh\nexit 0\n',
            'patchelf': '#!/bin/sh\ntouch "$TEST_STAGE/.patched"\nexit 0\n',
            'ldd': '''#!/bin/sh
if [ "${TEST_MISSING:-0}" = 1 ]; then echo 'libpq.so.5 => not found'; exit 0; fi
case "$1" in
  */addon.node) if [ -e "$TEST_STAGE/.patched" ]; then p="$TEST_STAGE/native/libpq.so.5"; else p="$TEST_PG/libpq.so.5"; fi
    printf 'libpq.so.5 => %s (0x1)\\n' "$p";;
esac
echo 'libc.so.6 => /lib/libc.so.6 (0x1)'
''',
        }
        for name, content in scripts.items():
            path = tools / name
            path.write_text(content)
            path.chmod(0o755)
        self.env = {**os.environ, 'PATH': str(tools) + os.pathsep + os.environ['PATH'],
                    'TEST_PG': str(self.root / 'pg/lib'), 'TEST_STAGE': str(self.root / 'dist/package')}

    def tearDown(self):
        self.tmp.cleanup()

    def run_packager(self, extra=None):
        return subprocess.run([sys.executable, str(PACKAGER), str(self.root / 'pg/lib'), str(self.root / 'COPYRIGHT')],
                              cwd=self.root, env={**self.env, **(extra or {})}, capture_output=True, text=True)

    def test_archive_contains_relative_dependencies_and_notice(self):
        result = self.run_packager()
        self.assertEqual(result.returncode, 0, result.stderr)
        with zipfile.ZipFile(self.root / 'dist/native-dependencies.zip') as archive:
            self.assertIsNone(archive.testzip())
            self.assertIn('native/libpq.so.5', archive.namelist())
            self.assertIn('licenses/postgresql-COPYRIGHT', archive.namelist())
            self.assertTrue(all(not name.startswith('/') for name in archive.namelist()))

    def test_missing_dependency_fails_closed(self):
        self.assertNotEqual(self.run_packager({'TEST_MISSING': '1'}).returncode, 0)

    def test_only_two_nonruntime_readmes_are_excluded_and_licenses_remain(self):
        for package in ('nan', 'bindings'):
            directory = self.root / 'node_modules' / package
            directory.mkdir()
            (directory / 'README.md').write_text('/' + 'Users' + '/example/public-documentation')
            (directory / 'LICENSE.md').write_text('synthetic public license')
            (directory / 'index.js').write_text('module.exports = {};')
        result = self.run_packager()
        self.assertEqual(result.returncode, 0, result.stderr)
        with zipfile.ZipFile(self.root / 'dist/native-dependencies.zip') as archive:
            for package in ('nan', 'bindings'):
                self.assertNotIn(f'node_modules/{package}/README.md', archive.namelist())
                self.assertIn(f'node_modules/{package}/LICENSE.md', archive.namelist())
                self.assertIn(f'node_modules/{package}/index.js', archive.namelist())

    def test_unrelated_readme_still_fails_privacy_scan(self):
        directory = self.root / 'node_modules' / 'other'
        directory.mkdir()
        (directory / 'README.md').write_text('/' + 'Users' + '/example/public-documentation')
        result = self.run_packager()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stderr.strip(), 'Staged archive failed a bounded privacy marker scan: marker=user_path location=dependency')

    def test_private_marker_fails_closed(self):
        (self.root / 'node_modules/private.txt').write_text('/' + 'Users' + '/example/private')
        result = self.run_packager()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stderr.strip(), 'Staged archive failed a bounded privacy marker scan: marker=user_path location=dependency')
        self.assertNotIn('example/private', result.stderr)

    def test_failed_scan_does_not_leave_stale_archive(self):
        archive = self.root / 'dist' / 'native-dependencies.zip'
        archive.parent.mkdir(parents=True)
        archive.write_bytes(b'old synthetic archive')
        (self.root / 'node_modules/private.txt').write_text('/' + 'Users' + '/example/private')
        result = self.run_packager()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stderr.strip(), 'Staged archive failed a bounded privacy marker scan: marker=user_path location=dependency')
        self.assertFalse(archive.exists())

    def test_private_key_in_native_file_emits_only_fixed_categories(self):
        marker = '-----BEGIN RSA PRIVATE KEY-----'
        (self.root / 'pg/lib/libpq.so.5').write_text('sensitive-fixture-' + marker + '-do-not-disclose')
        result = self.run_packager()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stderr.strip(), 'Staged archive failed a bounded privacy marker scan: marker=private_key location=native')
        for value in (marker, 'do-not-disclose', str(self.root), 'libpq.so.5'):
            self.assertNotIn(value, result.stderr)
        self.assertEqual(result.stdout, '')

    def test_secret_in_filename_is_not_echoed(self):
        name = 'nsec1' + 'synthetic-private-name'
        (self.root / 'node_modules' / name).write_text('fixture')
        result = self.run_packager()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stderr.strip(), 'Staged archive failed a bounded privacy marker scan: marker=nostr_secret location=dependency')
        self.assertNotIn(name, result.stderr)
        self.assertEqual(result.stdout, '')

    def test_environment_path_is_not_echoed(self):
        marker = '/' + 'confidential-home' + '/' + 'synthetic-sensitive-marker'
        (self.root / 'node_modules/private.txt').write_text(marker)
        result = self.run_packager({'HOME': marker})
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stderr.strip(), 'Staged archive failed a bounded privacy marker scan: marker=home_path location=dependency')
        self.assertNotIn(marker, result.stderr)
        self.assertEqual(result.stdout, '')

if __name__ == '__main__':
    unittest.main()
