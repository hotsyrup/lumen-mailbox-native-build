#!/usr/bin/env python3
"""Offline protocol-fixture tests. Generated certificates and keys are ephemeral."""
import base64
import hashlib
import hmac
import os
import socket
import ssl
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path
from fixture import PASSWORD, SALT, ITERATIONS, Server, packet, recv_packet

class ProtocolFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix='synthetic-pg-tls-')
        cls.cert = str(Path(cls.tmp.name) / 'cert.pem')
        cls.key = str(Path(cls.tmp.name) / 'key.pem')
        cls.othercert = str(Path(cls.tmp.name) / 'other.pem')
        otherkey = str(Path(cls.tmp.name) / 'other.key')
        for key, cert in [(cls.key, cls.cert), (otherkey, cls.othercert)]:
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-nodes', '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost', '-keyout', key, '-out', cert], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def plus_client(self, port, ca=None, hostname='localhost', corrupt_proof=False, corrupt_binding=False, expect_valid=True):
        ctx = ssl.create_default_context(cafile=ca or self.cert)
        with socket.create_connection(('127.0.0.1', port), timeout=3) as raw:
            raw.sendall(struct.pack('!II', 8, 80877103))
            self.assertEqual(raw.recv(1), b'S')
            with ctx.wrap_socket(raw, server_hostname=hostname) as conn:
                startup = struct.pack('!I', 196608) + b'user\0fixture-user\0database\0fixture\0\0'
                conn.sendall(struct.pack('!I', len(startup)+4) + startup)
                kind, body = recv_packet(conn)
                self.assertEqual(kind, b'R')
                code = struct.unpack('!I', body[:4])[0]
                if code != 10 or b'SCRAM-SHA-256-PLUS\0' not in body[4:]:
                    return False
                gs2 = b'p=tls-server-end-point,,'
                first_bare = b'n=fixture-user,r=clientnonce'
                first = gs2 + first_bare
                conn.sendall(packet(b'p', b'SCRAM-SHA-256-PLUS\0' + struct.pack('!i', len(first)) + first))
                kind, body = recv_packet(conn)
                self.assertEqual((kind, struct.unpack('!I', body[:4])[0]), (b'R', 11))
                server_first = body[4:]
                binding = gs2 + hashlib.sha256(conn.getpeercert(binary_form=True)).digest()
                if corrupt_binding:
                    binding = binding[:-1] + bytes([binding[-1] ^ 1])
                nonce = server_first.decode().split(',')[0][2:]
                final_without = b'c=' + base64.b64encode(binding) + b',r=' + nonce.encode()
                auth_message = first_bare + b',' + server_first + b',' + final_without
                salted = hashlib.pbkdf2_hmac('sha256', PASSWORD, SALT, ITERATIONS)
                mac = lambda k, m: hmac.new(k, m, hashlib.sha256).digest()
                ck = mac(salted, b'Client Key')
                cs = mac(hashlib.sha256(ck).digest(), auth_message)
                p = bytes(a ^ b for a, b in zip(ck, cs))
                if corrupt_proof:
                    p = bytes([p[0] ^ 1]) + p[1:]
                conn.sendall(packet(b'p', final_without + b',p=' + base64.b64encode(p)))
                if not expect_valid:
                    with self.assertRaises((EOFError, OSError)):
                        recv_packet(conn)
                    return False
                kind, body = recv_packet(conn)
                self.assertEqual((kind, struct.unpack('!I', body[:4])[0]), (b'R', 12))
                signature = mac(mac(salted, b'Server Key'), auth_message)
                valid_signature = hmac.compare_digest(body[4:], b'v=' + base64.b64encode(signature))
                if valid_signature:
                    self.assertEqual(struct.unpack('!I', recv_packet(conn)[1][:4])[0], 0)
                    self.assertEqual(recv_packet(conn), (b'Z', b'I'))
                    conn.sendall(packet(b'X'))
                return valid_signature

    def test_positive_verifies_channel_binding_and_client_proof(self):
        with Server(self.cert, self.key) as s:
            self.assertTrue(self.plus_client(s.port))
        self.assertEqual(s.chosen, 'SCRAM-SHA-256-PLUS')
        self.assertTrue(s.bound and s.proof_valid)
        self.assertEqual(s.queries, 0)
        self.assertIsNone(s.error)

    def test_fixture_rejects_tampered_binding_or_proof(self):
        for keyword in ('corrupt_binding', 'corrupt_proof'):
            with self.subTest(keyword=keyword), Server(self.cert, self.key) as s:
                self.plus_client(s.port, expect_valid=False, **{keyword: True})
            self.assertFalse(s.bound and s.proof_valid)
            self.assertEqual(s.queries, 0)

    def test_fixture_produces_rejected_signature(self):
        with Server(self.cert, self.key, 'bad_signature') as s:
            self.assertFalse(self.plus_client(s.port))
        self.assertTrue(s.bound and s.proof_valid)
        self.assertEqual(s.queries, 0)

    def test_fixture_emits_only_unbound_or_password_auth_and_no_auth(self):
        for mode in ('nonplus', 'cleartext', 'md5', 'trust'):
            with self.subTest(mode=mode), Server(self.cert, self.key, mode) as s:
                self.assertFalse(self.plus_client(s.port))
            self.assertEqual(s.queries, 0)

    def test_fixture_detects_unbound_or_password_submission(self):
        for mode in ('nonplus', 'cleartext', 'md5'):
            with self.subTest(mode=mode), Server(self.cert, self.key, mode) as s:
                context = ssl.create_default_context(cafile=self.cert)
                with socket.create_connection(('127.0.0.1', s.port), timeout=3) as raw:
                    raw.sendall(struct.pack('!II', 8, 80877103))
                    self.assertEqual(raw.recv(1), b'S')
                    with context.wrap_socket(raw, server_hostname='localhost') as conn:
                        startup = struct.pack('!I', 196608) + b'user\0fixture-user\0database\0fixture\0\0'
                        conn.sendall(struct.pack('!I', len(startup)+4) + startup)
                        recv_packet(conn)
                        payload = b'SCRAM-SHA-256\0' + struct.pack('!i', 1) + b'x' if mode == 'nonplus' else b'public-synthetic-password\0'
                        conn.sendall(packet(b'p', payload))
            self.assertTrue(s.disallowed_auth_submission)
            self.assertEqual(s.queries, 0)

    def test_rejects_bad_certificate_and_wrong_hostname(self):
        for ca, name in ((self.othercert, 'localhost'), (self.cert, '127.0.0.1')):
            with self.subTest(name=name), Server(self.cert, self.key) as s:
                with self.assertRaises(ssl.SSLCertVerificationError):
                    self.plus_client(s.port, ca=ca, hostname=name)
            self.assertEqual(s.queries, 0)

    def test_fixture_can_refuse_tls_without_receiving_plaintext(self):
        with Server(self.cert, self.key, 'no_tls') as s:
            with socket.create_connection(('127.0.0.1', s.port), timeout=3) as client:
                client.sendall(struct.pack('!II', 8, 80877103))
                self.assertEqual(client.recv(1), b'N')
        self.assertIsNone(s.error)
        self.assertEqual(s.queries, 0)

if __name__ == '__main__':
    unittest.main()
