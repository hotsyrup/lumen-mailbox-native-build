# Synthetic PostgreSQL channel-binding fixture

This is a **loopback-only, synthetic test fixture**, not a database or production
client. It contains no real credentials, messages, certificates, or keys. The
password string in the source is a public test constant. Tests use an ephemeral
`127.0.0.1` port and generate two short-lived self-signed test certificates and
private keys in a temporary directory, which is deleted when the tests complete.
The fixture never connects to Neon or any external network target.

Requirements: Python 3, OpenSSL CLI with `req -addext` support, and an execution
environment permitting loopback TCP. `test_libpq.py` additionally needs PostgreSQL
18-or-newer `libpq` discoverable by `ctypes.util.find_library`. The intended
target is Linux ARM64/glibc. The
fixture library tests use Python ctypes, so Node 24 is not needed for those tests;
testing a Node 24 native addon and final Neon packaging is a **separate** step.

From the repository root:

```sh
python3 -m unittest discover -s fixture -p test_fixture.py -v
python3 -m unittest discover -s fixture -p test_node_mock.py -v
python3 fixture/run-required-libpq.py
python3 fixture/run-required-node.py
```

`test_fixture.py` tests the server itself with a small synthetic Python client.
It checks successful SCRAM-SHA-256-PLUS, that the channel-binding input contains
the SHA-256 hash of the presented server certificate, valid client proof, a bad
binding or proof being rejected, invalid server signature being produced,
unbound-only and non-SASL challenge scenarios, and invalid CA/hostname errors.
These are fixture self-tests; they do **not** establish libpq or Node behavior.

`run-required-libpq.py` fails if libpq 18 is missing or if **any** libpq case
is skipped. It uses an explicit synthetic CA path and connects with
`sslmode=verify-full`, `channel_binding=require`, `require_auth=scram-sha-256`,
`gssencmode=disable` and `sslcertmode=disable`. It removes inherited `PG*`
environment variables during tests, and uses a numeric loopback host address to
prevent external DNS. Cases assert:

* SCRAM-PLUS success, correct certificate binding and client proof, followed by a
  successful synthetic query.
* Rejection of a server offering only unbound SCRAM; cleartext password; MD5;
  no-auth/trust; and a forged server signature, including pipelined auth success.
* Rejection of a server that declines TLS, with no plaintext fallback.
* Rejection of an untrusted CA and hostname mismatch.
* No query and no usable connection for each negative case.

The test-only CA override is used **only in this harness**, and must not be
introduced into a production URL validator. libpq's result must not be treated as
proof the Node native binding passes the options unchanged or loads on Neon.
Independently test the exact Node 24 Linux ARM64/glibc addon and bundled native
libraries against the same fixture; verify the runtime CA store and package
limits before any separate authorized live test.

`run-required-node.py` uses Node 24 to load the actual `pg-native` package; use
`STRICT_BINDING_ADDON` to point to the exact packaged module if it is not on the
Node resolution path. It fails explicitly if the addon cannot be loaded and runs
the same positive and negative connection scenarios, including proof of binding
and a successful synthetic query,
without opening a real database connection. This tests the loaded addon with an
explicit synthetic CA path; it does not exercise the production validator or
prove the Neon runtime has that same addon, native libraries, or system CA store.
`test_node_mock.py` tests only process plumbing using a fake module and no socket;
it must never be confused with the required native-addon test.

A failure or skipped test must not be reported as strict channel-binding
verification. The required runners fail if the necessary native library or
addon is unavailable.
