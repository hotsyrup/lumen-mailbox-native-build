#!/usr/bin/env python3
"""Actual local libpq protocol tests, strictly synthetic and loopback only.

Requires libpq 18, openssl, and a loopback-capable environment. This suite tests
libpq directly with a synthetic CA file. It does not test the Node addon, the
production URL validator, packaging, Neon, or a hosted Function.
"""
import ctypes
import ctypes.util
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from fixture import Server

LIBPQ = ctypes.util.find_library('pq')

@unittest.skipUnless(LIBPQ, 'libpq shared library is not installed')
class LibpqBinding(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lib = ctypes.CDLL(LIBPQ)
        cls.lib.PQlibVersion.restype = ctypes.c_int
        if cls.lib.PQlibVersion() < 180000:
            raise unittest.SkipTest('fixture requires libpq 18 or newer')
        cls.lib.PQconnectdb.argtypes = [ctypes.c_char_p]
        cls.lib.PQconnectdb.restype = ctypes.c_void_p
        cls.lib.PQstatus.argtypes = [ctypes.c_void_p]
        cls.lib.PQstatus.restype = ctypes.c_int
        cls.lib.PQfinish.argtypes = [ctypes.c_void_p]
        cls.lib.PQexec.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        cls.lib.PQexec.restype = ctypes.c_void_p
        cls.lib.PQresultStatus.argtypes = [ctypes.c_void_p]
        cls.lib.PQresultStatus.restype = ctypes.c_int
        cls.lib.PQclear.argtypes = [ctypes.c_void_p]
        cls.tmp = tempfile.TemporaryDirectory(prefix='synthetic-libpq-tls-')
        cls.cert = str(Path(cls.tmp.name) / 'cert.pem')
        cls.key = str(Path(cls.tmp.name) / 'key.pem')
        cls.othercert = str(Path(cls.tmp.name) / 'other.pem')
        for key, cert in [(cls.key, cls.cert), (str(Path(cls.tmp.name) / 'other.key'), cls.othercert)]:
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-nodes', '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost', '-keyout', key, '-out', cert], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # Prevent inherited libpq options from affecting this isolated fixture.
        cls.saved_env = {k: v for k, v in os.environ.items() if k.startswith('PG')}
        for key in cls.saved_env:
            del os.environ[key]

    @classmethod
    def tearDownClass(cls):
        os.environ.update(cls.saved_env)
        cls.tmp.cleanup()

    def connect(self, port, hostname='localhost', root=None):
        # Paths contain no quotes or backslashes in the harness-generated temp dir.
        root = root or self.cert
        if any(c in root for c in "'\\"):
            raise ValueError('unsupported synthetic CA path')
        info = (f"host={hostname} hostaddr=127.0.0.1 port={port} dbname=fixture "
                f"user=fixture-user password=fixture-password sslmode=verify-full "
                f"sslrootcert='{root}' channel_binding=require require_auth=scram-sha-256 "
                f"gssencmode=disable sslcertmode=disable connect_timeout=3")
        conn = self.lib.PQconnectdb(info.encode())
        self.assertTrue(conn, 'libpq returned no connection object')
        return conn

    def test_scram_plus_success_proves_tls_binding_and_query(self):
        with Server(self.cert, self.key) as s:
            conn = self.connect(s.port)
            try:
                self.assertEqual(self.lib.PQstatus(conn), 0, 'libpq did not authenticate')
                result = self.lib.PQexec(conn, b'SELECT 1')
                self.assertTrue(result)
                try:
                    self.assertEqual(self.lib.PQresultStatus(result), 2)
                finally:
                    self.lib.PQclear(result)
            finally:
                self.lib.PQfinish(conn)
        self.assertEqual(s.chosen, 'SCRAM-SHA-256-PLUS')
        self.assertTrue(s.bound and s.proof_valid)
        self.assertEqual(s.queries, 1)
        self.assertIsNone(s.error)

    def test_rejects_fallback_and_tampered_server_signature_without_query(self):
        for mode in ('no_tls', 'nonplus', 'cleartext', 'md5', 'trust', 'bad_signature'):
            with self.subTest(mode=mode), Server(self.cert, self.key, mode) as s:
                conn = self.connect(s.port)
                try:
                    self.assertNotEqual(self.lib.PQstatus(conn), 0, 'unexpected usable connection')
                finally:
                    self.lib.PQfinish(conn)
            self.assertEqual(s.queries, 0)
            self.assertIsNone(s.error, 'fixture observed a plaintext fallback')
            self.assertFalse(s.disallowed_auth_submission, 'client sent credentials or attempted unbound SASL')

    def test_rejects_untrusted_certificate_and_wrong_hostname_without_query(self):
        for hostname, root in (('localhost', self.othercert), ('127.0.0.1', self.cert)):
            with self.subTest(hostname=hostname), Server(self.cert, self.key) as s:
                conn = self.connect(s.port, hostname=hostname, root=root)
                try:
                    self.assertNotEqual(self.lib.PQstatus(conn), 0, 'unexpected usable connection')
                finally:
                    self.lib.PQfinish(conn)
            self.assertEqual(s.queries, 0)

if __name__ == '__main__':
    unittest.main()
