#!/usr/bin/env python3
"""Offline plumbing tests with a fake addon; not a channel-binding proof."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().with_name('node-fixture-client.cjs')

class NodeWorkerMock(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix='fixture-node-mock-')
        cls.module = Path(cls.tmp.name) / 'fake.cjs'
        cls.module.write_text("module.exports=class { connectSync(s) { if(!s.includes('hostaddr=127.0.0.1')||!s.includes('channel_binding=require')||!s.includes('sslmode=verify-full')||s.includes('port=9 ')) throw Error('synthetic'); } querySync(){return [{fixture:1}];} end(){} };\n")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def run_worker(self, addon, data='', args=()):
        env = {k:v for k,v in os.environ.items() if not k.startswith('PG') and k != 'NODE_OPTIONS'}
        env['STRICT_BINDING_ADDON'] = str(addon)
        p = subprocess.run(['node', str(SCRIPT), *args], input=data, capture_output=True, text=True, timeout=5, env=env)
        return p.returncode, p.stdout.strip()

    def test_missing_addon_fails_explicitly(self):
        self.assertEqual(self.run_worker(self.module.with_name('missing.cjs'), args=('--probe',)), (2, 'addon_unavailable'))

    def test_mock_load_and_fixed_conninfo_plumbing(self):
        self.assertEqual(self.run_worker(self.module, args=('--probe',)), (0, 'addon_loaded'))
        payload = json.dumps({'port': 12345, 'hostname': 'localhost', 'ca': str(Path(self.tmp.name) / 'synthetic-ca.pem')})
        self.assertEqual(self.run_worker(self.module, payload), (0, 'connected'))
        payload = json.dumps({'port': 9, 'hostname': 'localhost', 'ca': str(Path(self.tmp.name) / 'synthetic-ca.pem')})
        self.assertEqual(self.run_worker(self.module, payload), (0, 'rejected'))

    def test_external_hostname_rejected_before_any_connect(self):
        payload = json.dumps({'port': 12345, 'hostname': 'example.com', 'ca': str(Path(self.tmp.name) / 'synthetic-ca.pem')})
        self.assertEqual(self.run_worker(self.module, payload), (3, 'fixture_input_invalid'))

    def test_query_failure_is_not_reported_as_auth_rejection(self):
        bad_query = self.module.with_name('query-failure.cjs')
        bad_query.write_text("module.exports=class {connectSync(){} querySync(){throw Error('synthetic')} end(){}};\n")
        payload = json.dumps({'port': 12345, 'hostname': 'localhost', 'ca': str(Path(self.tmp.name) / 'synthetic-ca.pem')})
        self.assertEqual(self.run_worker(bad_query, payload), (4, 'query_failed'))

if __name__ == '__main__':
    unittest.main()
