#!/usr/bin/env python3
"""Test the user's original Bash entry, with offline downloads and isolated paths."""
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
README = (ROOT / 'README.md').read_text()
COMMAND = re.search(r'## 一键运行\n.*?```bash\n(.*?)\n```', README, re.S).group(1)
URL = 'https://raw.githubusercontent.com/slobys/SSL-Renewal/main/acme.sh'


class UniversalInstallCommandTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='ssl-install-command-test-')
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.bin = self.base / 'bin'
        self.bin.mkdir()
        self.shell_path = shutil.which('bash')
        self.python = shutil.which('python3')
        for name in ('bash', 'sh', 'mktemp', 'rm'):
            (self.bin / name).symlink_to(shutil.which(name))
        self.payload = self.base / 'payload.sh'
        self.payload.write_text('''#!/bin/sh
printf 'READY\\n'
IFS= read -r choice
printf 'CHOICE=%s\\n' "$choice"
exit "${INSTALL_EXIT:-0}"
''')
        self.env = dict(os.environ, PATH=str(self.bin), PAYLOAD=str(self.payload),
                        TEMP_LOG=str(self.base / 'temp-path'),
                        TOOL_LOG=str(self.base / 'tool'), DOWNLOAD_EXIT='0')

    def downloader(self):
        target = self.bin / 'curl'
        target.write_text('#!' + self.python + '\n' + '''import os, pathlib, sys
args = sys.argv[1:]
assert '--insecure' not in args, args
if args == ['-fsSL', 'https://raw.githubusercontent.com/slobys/SSL-Renewal/main/acme.sh']:
    pathlib.Path(os.environ['TOOL_LOG']).write_text('curl')
    sys.stdout.buffer.write(pathlib.Path(os.environ['PAYLOAD']).read_bytes())
elif '-o' in args and any(u.endswith('/openwrt_ip_ssl.sh') for u in args):
    pathlib.Path(args[args.index('-o') + 1]).write_text(
        '#!/bin/sh\\nIFS= read -r choice\\nprintf "OPENWRT=%s\\\\n" "$choice"\\n')
else:
    raise AssertionError('Unexpected download: ' + repr(args))
''')
        target.chmod(0o700)

    def run_command(self, input_text='2\n', expected=0, updates=None):
        result = subprocess.run([self.shell_path, '--noprofile', '--norc', '-c', COMMAND],
                                input=input_text, text=True, capture_output=True,
                                env=dict(self.env, **(updates or {})), timeout=10)
        self.assertEqual(expected, result.returncode, result.stdout + result.stderr)
        return result

    def test_readme_preserves_exact_original_command(self):
        section = README.split('## 一键运行', 1)[1].split('## 主菜单', 1)[0]
        self.assertEqual('bash <(curl -fsSL ' + URL + ')', COMMAND)
        self.assertEqual(1, section.count('```bash'))
        self.assertNotIn("sh -c '", section)
        self.assertLessEqual(len(README.splitlines()), 80)
        subprocess.run([self.shell_path, '-n', '-c', COMMAND], check=True)

    def test_readme_states_entry_requirements(self):
        section = README.split('## 一键运行', 1)[1].split('## 主菜单', 1)[0]
        for text in ('`bash`', '`curl`', '当前 Shell', '直接在软路由', '`acme.sh` 内'):
            self.assertIn(text, section)
        self.assertNotIn('无需云服务器、Bash', section)
        self.assertNotIn('下载失败不执行', section)

    def test_original_command_preserves_interactive_input(self):
        self.downloader()
        result = self.run_command()
        self.assertIn('CHOICE=2', result.stdout)
        self.assertEqual('curl', (self.base / 'tool').read_text())

    def test_installer_error_propagates(self):
        self.downloader()
        self.assertIn('READY', self.run_command(expected=17, updates={'INSTALL_EXIT': '17'}).stdout)

    def test_missing_bash_cannot_bootstrap_itself(self):
        self.downloader()
        (self.bin / 'bash').unlink()
        self.assertNotIn('READY', self.run_command(expected=127).stdout)

    def test_missing_curl_does_not_start_the_downloaded_script(self):
        # Process substitution's curl status is not Bash's exit status. Do not
        # claim the old command has the discarded wrapper's download guarantees.
        result = self.run_command()
        self.assertIn('curl', result.stderr)
        self.assertNotIn('READY', result.stdout)

    def test_shell_without_process_substitution_needs_bash_first(self):
        dash = shutil.which('dash')
        if not dash:
            self.skipTest('dash not installed')
        result = subprocess.run([dash, '-n', '-c', COMMAND], capture_output=True)
        self.assertNotEqual(0, result.returncode)

    def bootstrap_fixture(self, openwrt):
        # Rewrite only absolute host paths in the real entry, never run it on
        # the actual host. Both OS routes then execute through the README command.
        source = (ROOT / 'acme.sh').read_text()
        marker = self.base / 'openwrt_release'
        if openwrt:
            marker.touch()
        home = self.base / 'root'
        home.mkdir()
        source = source.replace('/etc/openwrt_release', str(marker))
        source = source.replace('/root/', str(home) + '/')
        self.payload.write_text(source)
        for name in ('mkdir', 'chmod', 'cp', 'mv', 'install'):
            (self.bin / name).symlink_to(shutil.which(name))
        (self.bin / 'id').write_text('#!/bin/sh\necho 0\n')
        (self.bin / 'id').chmod(0o700)
        return home

    def test_original_command_routes_to_openwrt_without_git_or_python(self):
        home = self.bootstrap_fixture(True)
        self.downloader()
        for name in ('git', 'python3', 'apt-get', 'yum', 'dnf'):
            path = self.bin / name
            path.write_text('#!/bin/sh\necho UNEXPECTED_SERVER_DEPENDENCY >&2\nexit 99\n')
            path.chmod(0o700)
        result = self.run_command(input_text='1\n')
        self.assertIn('OPENWRT=1', result.stdout)
        self.assertNotIn('UNEXPECTED_SERVER_DEPENDENCY', result.stdout + result.stderr)
        self.assertTrue((home / '.ssl-renewal/openwrt/openwrt_ip_ssl.sh').exists())
        self.assertFalse((home / 'acme_3.0.sh').exists())

    def test_real_bootstrap_linux_route(self):
        home = self.bootstrap_fixture(False)
        self.downloader()
        git = self.bin / 'git'
        git.write_text('#!' + self.python + '\n' + '''import pathlib, sys
args = sys.argv[1:]
assert args[0] == 'clone', args
repo = pathlib.Path(args[-1]); repo.mkdir(parents=True)
for name in ('acme.sh', 'acme_3.0.sh', 'dynamic_ip_cert.sh', 'remote_ip_ssl.sh', 'openwrt_ip_ssl.sh'):
    (repo / name).write_text('#!/bin/sh\\nIFS= read -r choice\\nprintf "LINUX=%s\\\\n" "$choice"\\n')
(repo / 'uninstall_server.py').write_text('# placeholder for offline installation test\\n')
''')
        git.chmod(0o700)
        result = self.run_command(input_text='5\n')
        self.assertIn('LINUX=5', result.stdout)
        self.assertTrue((home / 'acme_3.0.sh').exists())
        self.assertFalse((home / '.ssl-renewal/openwrt').exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
