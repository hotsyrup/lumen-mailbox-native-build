#!/usr/bin/env python3
"""Stage public runtime dependencies only; no app or credentials."""
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import zipfile

root = Path.cwd()
expected_libpq = Path(sys.argv[1]).resolve()
node_modules = root / 'node_modules'
stage = root / 'dist' / 'package'
if stage.exists():
    shutil.rmtree(stage)
stage.mkdir(parents=True)

def ignore(_directory, names):
    return {name for name in names if name in {'.bin', '.cache', '__pycache__'}}

shutil.copytree(node_modules, stage / 'node_modules', ignore=ignore, symlinks=False)
source = node_modules / 'libpq' / 'build' / 'Release'
addons = list(source.glob('*.node'))
if len(addons) != 1:
    raise SystemExit('Expected one compiled libpq addon')
staged_build = stage / 'node_modules' / 'libpq' / 'build'
shutil.rmtree(staged_build, ignore_errors=True)
(staged_build / 'Release').mkdir(parents=True)
addon = staged_build / 'Release' / addons[0].name
shutil.copy2(addons[0], addon)

def output(*args):
    return subprocess.run(args, check=True, text=True, capture_output=True).stdout

def deps(path):
    text = output('ldd', str(path))
    if 'not found' in text:
        raise SystemExit('Native library dependency was not found')
    return [(m.group(1), Path(m.group(2))) for m in
            re.finditer(r'^\s*(\S+)\s+=>\s+(/\S+)\s+\(', text, re.M)]

if not re.search(r'Machine:\s+AArch64', output('readelf', '-h', str(addon))):
    raise SystemExit('Addon is not AArch64 ELF')

system = {'libc.so.6', 'libm.so.6', 'libpthread.so.0', 'libdl.so.2', 'librt.so.1', 'libresolv.so.2'}
native = stage / 'native'
native.mkdir()
licenses = stage / 'licenses'
licenses.mkdir()
shutil.copyfile(Path(sys.argv[2]), licenses / 'postgresql-COPYRIGHT')
queue = deps(addon)
copied = set()
while queue:
    soname, library = queue.pop()
    if soname in system or soname in copied:
        continue
    if '/' in soname or not re.fullmatch(r'[A-Za-z0-9_.+-]+', soname):
        raise SystemExit('Unexpected native dependency name')
    if soname == 'libpq.so.5' and not library.resolve().is_relative_to(expected_libpq):
        raise SystemExit('Addon did not resolve the pinned libpq build')
    target = native / soname
    shutil.copy2(library.resolve(), target)
    copied.add(soname)
    queue.extend(deps(library))
if 'libpq.so.5' not in copied:
    raise SystemExit('Pinned libpq was not linked by the addon')
for package in ('libssl3t64', 'libstdc++6', 'libgcc-s1'):
    copyright_file = Path('/usr/share/doc') / package / 'copyright'
    if copyright_file.is_file():
        shutil.copyfile(copyright_file, licenses / (package + '-copyright'))
if any(name.startswith(('libssl.so', 'libcrypto.so')) for name in copied) and not (licenses / 'libssl3t64-copyright').is_file():
    raise SystemExit('OpenSSL license metadata is missing')
if 'libstdc++.so.6' in copied and not (licenses / 'libstdc++6-copyright').is_file():
    raise SystemExit('libstdc++ license metadata is missing')
if 'libgcc_s.so.1' in copied and not (licenses / 'libgcc-s1-copyright').is_file():
    raise SystemExit('libgcc license metadata is missing')

# Relative loader paths keep the binary independent of the CI build directory.
subprocess.run(['strip', '--strip-unneeded', str(addon)], check=True)
subprocess.run(['patchelf', '--set-rpath', '$ORIGIN/../../../../native', str(addon)], check=True)
for path in native.iterdir():
    subprocess.run(['strip', '--strip-unneeded', str(path)], check=True)
    subprocess.run(['patchelf', '--set-rpath', '$ORIGIN', str(path)], check=True)

clean_env = dict(os.environ)
clean_env.pop('LD_LIBRARY_PATH', None)
for path in [addon, *native.iterdir()]:
    result = subprocess.run(['ldd', str(path)], env=clean_env, text=True, capture_output=True, check=True)
    if 'not found' in result.stdout:
        raise SystemExit('Staged dependency closure is incomplete')
    for match in re.finditer(r'^\s*(\S+)\s+=>\s+(/\S+)\s+\(', result.stdout, re.M):
        soname, resolved = match.group(1), Path(match.group(2)).resolve()
        if soname not in system and not resolved.is_relative_to(native.resolve()):
            raise SystemExit('Non-system dependency escaped the staged directory')

versions = set()
for path in [addon, *native.iterdir()]:
    versions.update(re.findall(r'GLIBC_[0-9]+(?:\.[0-9]+)+', output('readelf', '--version-info', str(path))))
report = ('Native architecture: Linux AArch64\n'
          'PostgreSQL source: 18.6\n'
          'Node: ' + output('node', '--version').strip() + '\n'
          'Compiler: ' + output('gcc', '--version').splitlines()[0] + '\n'
          'OpenSSL: ' + output('openssl', 'version').strip() + '\n'
          'glibc build environment: ' + output('ldd', '--version').splitlines()[0] + '\n'
          'Included libraries: ' + ', '.join(sorted(copied)) + '\n'
          'External system ABI: glibc and its dynamic loader\n'
          'Required GLIBC symbol versions: ' + ', '.join(sorted(versions)) + '\n'
          'Native addon SHA-256: ' + hashlib.sha256(addon.read_bytes()).hexdigest() + '\n'
          + ''.join(path.name + ' SHA-256: ' + hashlib.sha256(path.read_bytes()).hexdigest() + '\n'
                    for path in sorted(native.iterdir()))
          + 'This is a synthetic dependency artifact, not a deployed Function.\n')
(stage / 'DEPENDENCIES.txt').write_text(report)

files = sorted(path for path in stage.rglob('*') if path.is_file())
size = sum(path.stat().st_size for path in files)
if len(files) > 4096 or size > 64 * 1024 * 1024:
    raise SystemExit('Unpacked dependency archive exceeds Function limits')
# Bounded privacy scan of names and file bytes; this cannot prove absence of
# every possible secret, so the public source and package still need review.
needles = [b'/Users/', b'/home/runner/', b'/workspace/',
           b'-----BEGIN PRIVATE KEY-----', b'-----BEGIN RSA PRIVATE KEY-----',
           b'-----BEGIN EC PRIVATE KEY-----', b'-----BEGIN OPENSSH PRIVATE KEY-----', b'nsec1']
for candidate in (os.environ.get('HOME'), os.environ.get('GITHUB_WORKSPACE'), sys.argv[3] if len(sys.argv) > 3 else None):
    if candidate and candidate != '/':
        needles.append(candidate.encode())
for path in files:
    data = path.read_bytes()
    name = path.relative_to(stage).as_posix().encode()
    if any(needle in data or needle in name for needle in needles):
        raise SystemExit('Staged archive failed a bounded privacy marker scan')
archive = root / 'dist' / 'native-dependencies.zip'
with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as z:
    for path in files:
        name = path.relative_to(stage).as_posix()
        info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
        info.create_system = 3
        info.external_attr = 0o100644 << 16
        z.writestr(info, path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
if archive.stat().st_size > 10 * 1024 * 1024:
    raise SystemExit('Compressed dependency archive exceeds Function limit')
print(report, end='')
print('Dependency archive:', len(files), 'files,', size, 'unpacked bytes,', archive.stat().st_size, 'ZIP bytes')
print('SHA-256:', hashlib.sha256(archive.read_bytes()).hexdigest())
