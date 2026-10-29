#!/usr/bin/env bash
# Dependency-only synthetic tests. Never use real credentials or services.
set -euo pipefail
test "$(uname -s)" = Linux && test "$(uname -m)" = aarch64
node -e 'if (process.versions.node !== "24.22.0") process.exit(1)'
case "$(ldd --version 2>&1 | head -1)" in *GLIBC*|*glibc*|*'GNU libc'*|*'GNU C Library'*) ;; *) echo 'glibc is required' >&2; exit 1;; esac

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/home" "$work/tmp" dist
export HOME="$work/home" TMPDIR="$work/tmp" npm_config_cache="$work/npm-cache"
unset PGHOST PGHOSTADDR PGPORT PGDATABASE PGUSER PGPASSWORD PGSERVICE PGSERVICEFILE PGOPTIONS PGSSLMODE PGSSLROOTCERT PGREQUIREAUTH SSL_CERT_FILE SSL_CERT_DIR OPENSSL_CONF OPENSSL_MODULES LD_PRELOAD NODE_OPTIONS || true

# PostgreSQL Global Development Group public release, checksum independently
# pinned from its official release directory. Never execute from an unverified tar.
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
  https://ftp.postgresql.org/pub/source/v18.6/postgresql-18.6.tar.bz2 -o "$work/postgresql.tar.bz2"
printf '%s  %s\n' '555610c24d53e4316da5b7d3fc25c279d96856d5e0e23ee308c328c5fa881d9f' "$work/postgresql.tar.bz2" | sha256sum --check --status
tar -xjf "$work/postgresql.tar.bz2" -C "$work"
(
  cd "$work/postgresql-18.6"
  ./configure --prefix=/opt/native-pg --with-openssl --without-readline --without-zlib --disable-rpath > /dev/null
  make -s -j4 > /dev/null
  make -s install DESTDIR="$work/root" > /dev/null
)
prefix="$work/root/opt/native-pg"
export PATH="$prefix/bin:$PATH" LD_LIBRARY_PATH="$prefix/lib"
pg_config --version
test "$(pg_config --libdir)" = "$prefix/lib"
test "$(pg_config --includedir)" = "$prefix/include"
python3 - <<'PY'
import ctypes
pq = ctypes.CDLL('libpq.so.5')
pq.PQlibVersion.restype = ctypes.c_int
assert pq.PQlibVersion() == 180006, 'Expected pinned libpq 18.6'
print('Pinned libpq 18.6 loaded')
PY

# Integrity-locked registry dependencies; lifecycle scripts are disabled except
# for the explicitly rebuilt native addon.
npm ci --ignore-scripts --no-audit --no-fund --registry=https://registry.npmjs.org/
npm rebuild libpq --build-from-source --ignore-scripts=false --no-audit --no-fund
node --test adapter/*.test.mjs
python3 -m unittest discover -s fixture -p test_fixture.py -v
python3 -m unittest discover -s fixture -p test_node_mock.py -v
python3 fixture/run-required-libpq.py
python3 fixture/run-required-node.py

# The runner trust-store check is not evidence of trust in any other runtime.
test -s /etc/ssl/certs/ca-certificates.crt
openssl crl2pkcs7 -nocrl -certfile /etc/ssl/certs/ca-certificates.crt | openssl pkcs7 -print_certs -noout > /dev/null
echo 'Runner system CA bundle is present and parseable.'
PYTHONDONTWRITEBYTECODE=1 python3 scripts/test_package.py -v
python3 scripts/package.py "$prefix/lib" "$work/postgresql-18.6/COPYRIGHT" "$work"
rm -rf dist/extracted
python3 - <<'PY'
import zipfile
with zipfile.ZipFile('dist/native-dependencies.zip') as archive:
    assert archive.testzip() is None
    archive.extractall('dist/extracted')
PY
# Verify the actual uploaded bytes, not only the pre-archive staging directory.
env -u LD_LIBRARY_PATH STRICT_BINDING_ADDON="$PWD/dist/extracted/node_modules/pg-native" python3 fixture/run-required-node.py
echo 'Synthetic ARM64 checks complete; Neon runtime validation remains outstanding.'
