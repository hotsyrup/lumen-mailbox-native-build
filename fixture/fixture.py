#!/usr/bin/env python3
"""Synthetic loopback-only PostgreSQL TLS/SCRAM-PLUS test server.

No external services, user credentials or real data. Certificates are generated
in a temporary directory by the test runner. Do not use as a database server.
"""
import base64
import hashlib
import hmac
import os
import socket
import ssl
import struct
import threading

PASSWORD = b'fixture-password'
USER = 'fixture-user'
SALT = b'fixture-salt-123'
ITERATIONS = 4096

def readn(sock, size):
    if size < 0 or size > 65536:
        raise ValueError('oversize packet')
    data = b''
    while len(data) < size:
        part = sock.recv(size - len(data))
        if not part:
            raise EOFError('closed')
        data += part
    return data

def packet(kind, body=b''):
    return kind + struct.pack('!I', len(body) + 4) + body

def auth(code, payload=b''):
    return packet(b'R', struct.pack('!I', code) + payload)

def recv_packet(sock):
    kind = readn(sock, 1)
    size = struct.unpack('!I', readn(sock, 4))[0]
    return kind, readn(sock, size - 4)

def attrs(message):
    values = {}
    for field in message.decode('ascii').split(','):
        if len(field) < 3 or field[1] != '=' or field[0] in values:
            raise ValueError('bad SCRAM attribute')
        values[field[0]] = field[2:]
    return values

def h(key, message):
    return hmac.new(key, message, hashlib.sha256).digest()

def proof(first_bare, server_first, final_without_proof):
    salted = hashlib.pbkdf2_hmac('sha256', PASSWORD, SALT, ITERATIONS)
    client_key = h(salted, b'Client Key')
    stored_key = hashlib.sha256(client_key).digest()
    message = b','.join((first_bare, server_first, final_without_proof))
    signature = h(stored_key, message)
    p = bytes(a ^ b for a, b in zip(client_key, signature))
    return p, h(h(salted, b'Server Key'), message)

class Server:
    """One connection, only 127.0.0.1; records facts but never logs input."""
    def __init__(self, cert, key, mode='plus'):
        self.mode = mode
        with open(cert, encoding='ascii') as f:
            self.certificate_digest = hashlib.sha256(ssl.PEM_cert_to_DER_cert(f.read())).digest()
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(cert, key)
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.listener.bind(('127.0.0.1', 0))
        except BaseException:
            self.listener.close()
            raise
        self.listener.listen(1)
        self.listener.settimeout(6)
        self.port = self.listener.getsockname()[1]
        self.chosen = None
        self.bound = False
        self.proof_valid = False
        self.disallowed_auth_submission = False
        self.queries = 0
        self.error = None
        self.thread = threading.Thread(target=self._run, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.thread.join(8)
        self.listener.close()
        if self.thread.is_alive():
            raise RuntimeError('fixture server did not terminate')

    def _run(self):
        try:
            raw, address = self.listener.accept()
            with raw:
                raw.settimeout(5)
                if address[0] != '127.0.0.1':
                    raise ValueError('non-loopback client')
                if readn(raw, 8) != struct.pack('!II', 8, 80877103):
                    raise ValueError('expected SSLRequest')
                if self.mode == 'no_tls':
                    raw.sendall(b'N')
                    # Verify that a strict client does not fall back to plaintext.
                    try:
                        data = raw.recv(1)
                    except (OSError, TimeoutError):
                        data = b''
                    if data:
                        self.error = 'plaintext_fallback'
                    return
                raw.sendall(b'S')
                with self.context.wrap_socket(raw, server_side=True) as conn:
                    conn.settimeout(5)
                    length = struct.unpack('!I', readn(conn, 4))[0]
                    startup = readn(conn, length - 4)
                    if not startup.startswith(struct.pack('!I', 196608)):
                        raise ValueError('unexpected startup')
                    if self.mode == 'trust':
                        conn.sendall(auth(0) + packet(b'Z', b'I'))
                    elif self.mode == 'cleartext':
                        conn.sendall(auth(3))
                    elif self.mode == 'md5':
                        conn.sendall(auth(5, b'abcd'))
                    else:
                        mechs = b'SCRAM-SHA-256\0\0' if self.mode == 'nonplus' else b'SCRAM-SHA-256-PLUS\0SCRAM-SHA-256\0\0'
                        conn.sendall(auth(10, mechs))
                        kind, initial = recv_packet(conn)
                        if kind != b'p' or b'\0' not in initial:
                            raise ValueError('expected SASL initial')
                        if self.mode == 'nonplus':
                            self.disallowed_auth_submission = True
                        mech, rest = initial.split(b'\0', 1)
                        self.chosen = mech.decode('ascii')
                        if mech != b'SCRAM-SHA-256-PLUS' or len(rest) < 4:
                            return
                        n = struct.unpack('!i', rest[:4])[0]
                        first = rest[4:]
                        if n != len(first) or not first.startswith(b'p=tls-server-end-point,,'):
                            raise ValueError('invalid GS2 header')
                        first_bare = first[len(b'p=tls-server-end-point,,'):]
                        nonce = attrs(first_bare).get('r', '')
                        if not nonce or ',' in nonce:
                            raise ValueError('invalid nonce')
                        server_first = ('r=' + nonce + 'fixture-server-nonce,s=' + base64.b64encode(SALT).decode() + ',i=' + str(ITERATIONS)).encode()
                        conn.sendall(auth(11, server_first))
                        kind, final = recv_packet(conn)
                        if kind != b'p' or b',p=' not in final:
                            raise ValueError('missing proof')
                        final_without, encoded_proof = final.rsplit(b',p=', 1)
                        final_attrs = attrs(final_without)
                        expected_binding = b'p=tls-server-end-point,,' + self.certificate_digest
                        self.bound = hmac.compare_digest(base64.b64decode(final_attrs['c'], validate=True), expected_binding)
                        expected_proof, server_signature = proof(first_bare, server_first, final_without)
                        self.proof_valid = hmac.compare_digest(base64.b64decode(encoded_proof, validate=True), expected_proof)
                        if not self.bound or not self.proof_valid or final_attrs.get('r') != nonce + 'fixture-server-nonce':
                            raise ValueError('proof or channel binding failed')
                        if self.mode == 'bad_signature':
                            server_signature = b'\0' * len(server_signature)
                        conn.sendall(auth(12, b'v=' + base64.b64encode(server_signature)) + auth(0) + packet(b'Z', b'I'))
                    # Observe whether the client sends a SQL query. Auth failures
                    # and TLS failures should close without sending one.
                    while True:
                        kind, body = recv_packet(conn)
                        if kind == b'X':
                            return
                        if kind == b'Q':
                            self.queries += 1
                            # A minimal result for SELECT 1; fixture is not SQL.
                            field = b'fixture\0' + struct.pack('!IhIhih', 0, 0, 23, 4, -1, 0)
                            rowdesc = packet(b'T', struct.pack('!H', 1) + field)
                            data = packet(b'D', struct.pack('!H', 1) + struct.pack('!I', 1) + b'1')
                            conn.sendall(rowdesc + data + packet(b'C', b'SELECT 1\0') + packet(b'Z', b'I'))
                        elif kind == b'p':
                            # A password or unbound SASL attempt is never accepted.
                            self.disallowed_auth_submission = True
                            return
                        else:
                            return
        except (EOFError, OSError, ssl.SSLError, TimeoutError):
            pass  # Normal for a rejecting client or certificate failure.
        except Exception as exc:
            self.error = type(exc).__name__
