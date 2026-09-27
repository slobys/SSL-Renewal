#!/usr/bin/env python3
"""Generate/check the HTTPS consistency manifest; this is not a code signature.
Run after modifying runtime code: python3 tools/update_checksums.py
CI/read-only validation: python3 tools/update_checksums.py --check
"""
import argparse
import hashlib
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
FILES = ('acme.sh', 'acme_3.0.sh', 'dynamic_ip_cert.sh', 'remote_ip_ssl.sh',
         'openwrt_ip_ssl.sh', 'uninstall_server.py')


def render():
    result = []
    for name in FILES:
        path = ROOT / name
        if path.is_symlink():
            raise ValueError('Runtime file cannot be a symlink: ' + name)
        content = path.read_bytes()
        if not content:
            raise ValueError('Runtime file is empty: ' + name)
        result.append(hashlib.sha256(content).hexdigest() + '  ' + name + '\n')
    return ''.join(result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    options = parser.parse_args()
    manifest = ROOT / 'SHA256SUMS'
    expected = render()
    if options.check:
        if not manifest.is_file() or manifest.read_text() != expected:
            print('SHA256SUMS is stale; run python3 tools/update_checksums.py', file=sys.stderr)
            return 1
        print('SHA256SUMS matches all six runtime files')
        return 0
    if manifest.is_symlink():
        raise ValueError('Refusing a symlink manifest')
    manifest.write_text(expected)
    print('Updated SHA256SUMS for six runtime files')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)
