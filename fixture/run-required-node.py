#!/usr/bin/env python3
"""Run Node 24 pg-native fixture tests; missing addon or any skip is failure."""
import sys
import unittest
from pathlib import Path

suite = unittest.defaultTestLoader.discover(str(Path(__file__).resolve().parent), pattern='test_native_addon.py')
result = unittest.TextTestRunner(verbosity=2).run(suite)
if not result.wasSuccessful() or result.skipped or result.testsRun != 3:
    print('Required Node native-addon protocol verification incomplete.', file=sys.stderr)
    raise SystemExit(1)
print('All required synthetic Node native-addon tests passed.')
