#!/usr/bin/env python3
"""Exercise exact pg-native addon against synthetic loopback TLS/SCRAM fixture.

Must not silently skip: missing Node 24 or addon fails the suite. No credentials,
real service, or production validator are used. The caller must identify the
actual packaged addon with STRICT_BINDING_ADDON when it is not on Node's path.
"""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from fixture import Server

SCRIPT = Path(__file__).resolve().with_name('node-fixture-client.cjs')

def run_node(port=None, hostname=None, ca=None, probe=False):
    # No inherited PostgreSQL connection parameters or runtime injection.
    env = {k: v for k, v in os.environ.items() if not k.startswith('PG') and k != 'NODE_OPTIONS'}
    data = '' if probe else json.dumps({'port': port, 'hostname': hostname, 'ca': ca})
    p = subprocess.run(['node', str(SCRIPT)] + (['--probe'] if probe else []), input=data,
                       capture_output=True, text=True, timeout=10, env=env)
    return p.returncode, p.stdout.strip()

class NativeAddonBinding(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        status, result = run_node(probe=True)
        if status != 0 or result != 'addon_loaded':
            raise RuntimeError('Required Node 24 pg-native addon could not be loaded')
        cls.tmp = tempfile.TemporaryDirectory(prefix='synthetic-node-pg-tls-')
        cls.cert = str(Path(cls.tmp.name) / 'cert.pem')
        cls.key = str(Path(cls.tmp.name) / 'key.pem')
        cls.othercert = str(Path(cls.tmp.name) / 'other.pem')
        for key, cert in [(cls.key, cls.cert), (str(Path(cls.tmp.name) / 'other.key'), cls.othercert)]:
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-nodes', '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost', '-keyout', key, '-out', cert], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_scram_plus_success_is_bound_to_tls(self):
        with Server(self.cert, self.key) as s:
            status, result = run_node(s.port, 'localhost', self.cert)
            self.assertEqual((status, result), (0, 'connected'))
        self.assertEqual(s.chosen, 'SCRAM-SHA-256-PLUS')
        self.assertTrue(s.bound and s.proof_valid)
        self.assertEqual(s.queries, 1)
        self.assertIsNone(s.error)

    def test_rejects_downgrade_and_bad_signature_before_query(self):
        for mode in ('no_tls', 'nonplus', 'cleartext', 'md5', 'trust', 'bad_signature'):
            with self.subTest(mode=mode), Server(self.cert, self.key, mode) as s:
                self.assertEqual(run_node(s.port, 'localhost', self.cert), (0, 'rejected'))
            self.assertEqual(s.queries, 0)
            self.assertFalse(s.disallowed_auth_submission)
            self.assertIsNone(s.error)

    def test_rejects_invalid_ca_or_hostname_before_query(self):
        for hostname, root in (('localhost', self.othercert), ('127.0.0.1', self.cert)):
            with self.subTest(hostname=hostname), Server(self.cert, self.key) as s:
                self.assertEqual(run_node(s.port, hostname, root), (0, 'rejected'))
            self.assertEqual(s.queries, 0)
            self.assertFalse(s.disallowed_auth_submission)
            self.assertIsNone(s.error)

if __name__ == '__main__':
    unittest.main()
