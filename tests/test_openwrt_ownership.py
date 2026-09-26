#!/usr/bin/env python3
"""Regression for OpenWrt without stat: real ash/ls/awk, no router or CA access."""
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'openwrt_ip_ssl.sh'


class OpenWrtOwnershipTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='ssl-ownership-')
        self.addCleanup(self.tmp.cleanup)
        self.p = Path(self.tmp.name)
        self.bin = self.p / 'bin'
        self.bin.mkdir()
        self.base = self.p / 'private state with spaces'
        self.run = self.p / 'runtime with spaces'
        self.sh = shutil.which('sh')
        self.busybox = shutil.which('busybox')
        # Do not inherit /bin or /usr/bin: stat is genuinely absent, not mocked
        # by a GNU tool that just happens to work on the development host.
        for name in ('ls', 'awk', 'mkdir', 'chmod', 'id', 'date'):
            (self.bin / name).symlink_to(shutil.which(name))
        self.env = dict(os.environ, PATH=str(self.bin),
                        SSL_RENEWAL_OPENWRT_BASE=str(self.base),
                        SSL_RENEWAL_OPENWRT_RUN=str(self.run))

    def command(self, name, text):
        path = self.bin / name
        if path.is_symlink() or path.exists():
            path.unlink()
        path.write_text('#!/bin/sh\n' + text + '\n')
        path.chmod(0o700)

    def shell(self, body, input_text='', interpreter=None):
        return subprocess.run((interpreter or [self.sh]) + ['-c',
            'set -eu; SSL_RENEWAL_OPENWRT_LIBRARY=1; . "$1"; ' + body,
            'ownership-test', str(SCRIPT)], env=self.env, text=True,
            input=input_text, capture_output=True, timeout=10)

    def assert_ok(self, result):
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertNotIn('stat: not found', result.stderr)

    def test_private_directories_without_stat(self):
        r = self.shell('if command -v stat >/dev/null 2>&1; then exit 99; fi; ow_dirs; echo READY')
        self.assert_ok(r)
        self.assertIn('READY', r.stdout)
        for path in (self.base, self.run):
            self.assertEqual(0o700, path.stat().st_mode & 0o777)

    def test_menu_application_reaches_first_prompt_without_stat(self):
        r = self.shell('ow_require() { :; }; ow_setup; echo CANCELLED', '0\n')
        self.assert_ok(r)
        self.assertIn('地址类型', r.stdout)
        self.assertIn('CANCELLED', r.stdout)
        self.assertEqual([], list(self.base.iterdir()))

    def test_minimal_busybox_ash_and_applets_without_stat(self):
        if not self.busybox:
            self.skipTest('BusyBox is not installed on this test runner')
        for path in self.bin.iterdir():
            path.unlink()
            path.symlink_to(self.busybox)
        r = self.shell('if command -v stat >/dev/null 2>&1; then exit 99; fi; '
                       'ow_require() { :; }; ow_setup; echo READY', '0\n',
                       interpreter=[self.busybox, 'ash'])
        self.assert_ok(r)
        self.assertIn('READY', r.stdout)

    def test_broken_stat_is_not_called(self):
        self.command('stat', 'echo UNEXPECTED_STAT >&2; exit 127')
        r = self.shell('ow_dirs')
        self.assert_ok(r)
        self.assertNotIn('UNEXPECTED_STAT', r.stdout + r.stderr)

    def test_existing_data_preserved(self):
        self.base.mkdir()
        (self.base / 'saved.conf').write_text('configuration stays')
        self.base.chmod(0o755)
        self.assert_ok(self.shell('ow_dirs; ow_dirs'))
        self.assertEqual('configuration stays', (self.base / 'saved.conf').read_text())
        self.assertEqual(0o700, self.base.stat().st_mode & 0o777)

    def test_non_owner_directory_still_rejected_before_chmod(self):
        real_ls = shlex.quote(shutil.which('ls'))
        for target in (self.base, self.run):
            with self.subTest(target=target.name):
                self.base.mkdir(exist_ok=True)
                self.run.mkdir(exist_ok=True)
                self.base.chmod(0o755)
                self.run.chmod(0o755)
                self.env['REJECT_PATH'] = str(target)
                self.command('ls', 'for arg do last=$arg; done\n'
                    'if [ "$last" = "$REJECT_PATH" ]; then\n'
                    '  printf "drwxr-xr-x 2 %s 0 4096 Jan 1 00:00 target\\n" ' + str(os.getuid() + 1) + '\n'
                    'else exec ' + real_ls + ' "$@"; fi')
                r = self.shell('ow_dirs; echo UNSAFE_SUCCESS')
                self.assertNotEqual(0, r.returncode)
                self.assertIn('管理目录所有者不正确', r.stdout)
                self.assertNotIn('UNSAFE_SUCCESS', r.stdout)
                self.assertEqual(0o755, self.base.stat().st_mode & 0o777)
                self.assertEqual(0o755, self.run.stat().st_mode & 0o777)

    def test_failed_metadata_read_has_distinct_error(self):
        for text in ('exit 1', 'printf "drwx------ 2 0 0 1 Jan 1 00:00 x\\n"; exit 1'):
            with self.subTest(text=text):
                self.command('ls', text)
                r = self.shell('ow_dirs; echo UNSAFE_SUCCESS')
                self.assertNotEqual(0, r.returncode)
                self.assertIn('无法读取管理目录所有者', r.stdout)
                self.assertNotIn('管理目录所有者不正确', r.stdout)
                self.assertNotIn('UNSAFE_SUCCESS', r.stdout)

    def test_invalid_or_empty_metadata_fails_closed(self):
        for text in ('', 'not a directory', 'drwx------ 2 root 0 1 Jan 1 00:00 x',
                     'drwx------ 2 12x 0 1 Jan 1 00:00 x',
                     'lrwx------ 2 0 0 1 Jan 1 00:00 x'):
            with self.subTest(text=text):
                self.command('ls', "printf '%s\\n' " + shlex.quote(text))
                r = self.shell('ow_dirs; echo UNSAFE_SUCCESS')
                self.assertNotEqual(0, r.returncode)
                self.assertIn('无法读取管理目录所有者', r.stdout)
                self.assertNotIn('UNSAFE_SUCCESS', r.stdout)

    def test_symlink_directory_still_rejected(self):
        outside = self.p / 'outside'
        outside.mkdir()
        outside.chmod(0o755)
        for target in (self.base, self.run):
            with self.subTest(target=target.name):
                target.symlink_to(outside, target_is_directory=True)
                r = self.shell('ow_dirs; echo UNSAFE_SUCCESS')
                self.assertNotEqual(0, r.returncode)
                self.assertIn('不能是符号链接', r.stdout)
                self.assertNotIn('UNSAFE_SUCCESS', r.stdout)
                self.assertEqual(0o755, outside.stat().st_mode & 0o777)
                target.unlink()

    def test_directory_creation_failure_is_reported(self):
        self.command('mkdir', 'exit 1')
        r = self.shell('ow_dirs; echo UNSAFE_SUCCESS')
        self.assertNotEqual(0, r.returncode)
        self.assertIn('无法创建管理目录', r.stdout)
        self.assertNotIn('UNSAFE_SUCCESS', r.stdout)

    def test_failed_current_uid_is_not_an_owner_mismatch(self):
        for text in ('exit 1', 'echo root'):
            with self.subTest(text=text):
                self.command('id', text)
                r = self.shell('ow_dirs; echo UNSAFE_SUCCESS')
                self.assertNotEqual(0, r.returncode)
                self.assertIn('无法读取当前用户 UID', r.stdout)
                self.assertNotIn('UNSAFE_SUCCESS', r.stdout)


if __name__ == '__main__':
    unittest.main(verbosity=2)
