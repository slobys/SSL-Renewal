#!/usr/bin/env python3
"""A release cannot pass tests with stale component hashes."""
import hashlib
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ChecksumTests(unittest.TestCase):
    def test_manifest_complete_exact_and_current(self):
        names = {'acme.sh', 'acme_3.0.sh', 'openwrt_ip_ssl.sh', 'dynamic_ip_cert.sh',
                 'remote_ip_ssl.sh', 'uninstall_server.py'}
        records = (ROOT / 'SHA256SUMS').read_text().splitlines()
        self.assertEqual(len(names), len(records))
        found = set()
        for record in records:
            digest, name = record.split('  ')
            self.assertIn(name, names)
            self.assertNotIn(name, found)
            found.add(name)
            self.assertEqual(hashlib.sha256((ROOT / name).read_bytes()).hexdigest(), digest)
        self.assertEqual(names, found)

    def test_generator_check_does_not_modify_manifest(self):
        before = (ROOT / 'SHA256SUMS').read_bytes()
        subprocess.run([sys.executable, '-B', str(ROOT/'tools/update_checksums.py'), '--check'],
                       check=True, capture_output=True, text=True)
        self.assertEqual(before, (ROOT / 'SHA256SUMS').read_bytes())


if __name__ == '__main__':
    unittest.main(verbosity=2)
