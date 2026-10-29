#!/usr/bin/env python3
"""Run actual libpq fixture checks; a missing library or any skip is failure."""
import sys
import unittest
from pathlib import Path

suite = unittest.defaultTestLoader.discover(str(Path(__file__).resolve().parent), pattern='test_libpq.py')
result = unittest.TextTestRunner(verbosity=2).run(suite)
if not result.wasSuccessful() or result.skipped or result.testsRun != 3:
    print('Required libpq protocol verification incomplete.', file=sys.stderr)
    raise SystemExit(1)
print('All required synthetic libpq tests passed.')
