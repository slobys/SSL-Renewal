#!/usr/bin/env python3
"""Test the exact universal command from README without network or host writes."""
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
COMMAND = re.search(r'## 一键运行\n.*?```sh\n(.*?)\n```', README, re.S).group(1)
URL = 'https://raw.githubusercontent.com/slobys/SSL-Renewal/main/acme.sh'


class UniversalInstallCommandTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='ssl-install-command-test-')
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.bin = self.base / 'bin'
        self.bin.mkdir()
        self.shell_path = shutil.which('sh')
        self.python = shutil.which('python3')
        for name in ('sh', 'mktemp', 'rm'):
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

    def downloader(self, name):
        target = self.bin / name
        target.write_text('#!' + self.python + '\n' + '''import os, pathlib, sys
args = sys.argv[1:]
name = pathlib.Path(sys.argv[0]).name
flag = '-o' if name == 'curl' else '-O'
if name == 'curl':
    assert args[0] == '-q' and '-fsSL' in args, args
path = pathlib.Path(args[args.index(flag) + 1])
assert 'https://raw.githubusercontent.com/slobys/SSL-Renewal/main/acme.sh' in args, args
assert '--insecure' not in args and '--no-check-certificate' not in args, args
pathlib.Path(os.environ['TEMP_LOG']).write_text(str(path))
pathlib.Path(os.environ['TOOL_LOG']).write_text(name)
path.write_bytes(pathlib.Path(os.environ['PAYLOAD']).read_bytes())
sys.exit(int(os.environ['DOWNLOAD_EXIT']))
''')
        target.chmod(0o700)

    def run_command(self, input_text='2\n', expected=0, updates=None, interpreter=None):
        result = subprocess.run((interpreter or [self.shell_path]) + ['-c', COMMAND],
                                input=input_text, text=True, capture_output=True,
                                env=dict(self.env, **(updates or {})), timeout=10)
        self.assertEqual(expected, result.returncode, result.stdout + result.stderr)
        if (self.base / 'temp-path').exists():
            self.assertFalse(Path((self.base / 'temp-path').read_text()).exists())
        return result

    def test_readme_has_one_portable_install_command(self):
        section = README.split('## 一键运行', 1)[1].split('## 主菜单', 1)[0]
        self.assertEqual(1, section.count('```sh'))
        self.assertEqual(1, COMMAND.count(URL))
        self.assertNotIn('<(', COMMAND)
        self.assertNotIn('| sh', COMMAND)
        self.assertLessEqual(len(README.splitlines()), 80)
        subprocess.run([self.shell_path, '-n', '-c', COMMAND], check=True)

    def test_curl_only_preserves_menu_input_and_cleans_temp(self):
        self.downloader('curl')
        result = self.run_command()
        self.assertIn('CHOICE=2', result.stdout)
        self.assertEqual('curl', (self.base / 'tool').read_text())

    def test_wget_only_preserves_menu_input_and_cleans_temp(self):
        self.downloader('wget')
        self.assertIn('CHOICE=2', self.run_command().stdout)
        self.assertEqual('wget', (self.base / 'tool').read_text())

    def test_curl_preferred_when_both_installed(self):
        self.downloader('curl')
        self.downloader('wget')
        self.run_command()
        self.assertEqual('curl', (self.base / 'tool').read_text())

    def test_download_failure_never_executes_partial_file(self):
        for name in ('curl', 'wget'):
            with self.subTest(name=name):
                self.downloader(name)
                result = self.run_command(expected=23, updates={'DOWNLOAD_EXIT': '23'})
                self.assertNotIn('READY', result.stdout)
                (self.bin / name).unlink()

    def test_empty_download_rejected(self):
        self.downloader('curl')
        self.payload.write_text('')
        self.run_command(expected=1)

    def test_syntax_error_does_not_run_earlier_valid_commands(self):
        self.downloader('wget')
        self.payload.write_text('echo SHOULD_NOT_RUN\nif then\n')
        result = self.run_command(expected=2)
        self.assertNotIn('SHOULD_NOT_RUN', result.stdout)

    def test_installer_error_propagates(self):
        self.downloader('curl')
        self.assertIn('READY', self.run_command(expected=17, updates={'INSTALL_EXIT': '17'}).stdout)

    def test_no_downloader_does_not_run_installer(self):
        self.assertNotIn('READY', self.run_command(expected=127).stdout)

    def test_ash_and_bash_can_run_the_same_command(self):
        self.downloader('wget')
        interpreters = []
        if shutil.which('busybox'):
            interpreters.append([shutil.which('busybox'), 'ash'])
        if shutil.which('bash'):
            interpreters.append([shutil.which('bash'), '--noprofile', '--norc'])
        for interpreter in interpreters:
            with self.subTest(interpreter=interpreter):
                self.assertIn('CHOICE=2', self.run_command(interpreter=interpreter).stdout)

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

    def test_real_bootstrap_openwrt_route_without_bash_or_git(self):
        home = self.bootstrap_fixture(True)
        self.downloader('wget')
        downloader = self.bin / 'wget'
        original = downloader.read_text()
        native = '#!/bin/sh\nIFS= read -r choice\nprintf "OPENWRT=%s\\n" "$choice"\n'
        extra = ("\nif any(u.endswith('/openwrt_ip_ssl.sh') for u in args):\n"
                 "    out = pathlib.Path(args[args.index('-O') + 1])\n"
                 "    out.write_text(" + repr(native) + ")\n    sys.exit(0)\n")
        original = original.replace("flag = '-o' if name == 'curl' else '-O'\n",
                                    "flag = '-o' if name == 'curl' else '-O'\n" + extra)
        downloader.write_text(original)
        result = self.run_command(input_text='1\n')
        self.assertIn('OPENWRT=1', result.stdout)
        self.assertTrue((home / '.ssl-renewal/openwrt/openwrt_ip_ssl.sh').exists())
        self.assertFalse((home / 'acme_3.0.sh').exists())

    def test_real_bootstrap_linux_route(self):
        home = self.bootstrap_fixture(False)
        self.downloader('curl')
        bash = self.bin / 'bash'
        bash.write_text('#!/bin/sh\nif [ "$1" = -n ]; then exec sh "$@"; fi\nexec sh "$@"\n')
        bash.chmod(0o700)
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
        result = self.run_command(input_text='6\n')
        self.assertIn('LINUX=6', result.stdout)
        self.assertTrue((home / 'acme_3.0.sh').exists())
        self.assertFalse((home / '.ssl-renewal/openwrt').exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
