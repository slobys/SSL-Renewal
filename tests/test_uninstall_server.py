#!/usr/bin/env python3
"""Filesystem/cron uninstall regressions. All effects confined to a temp fixture."""
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('sslr_uninstall', ROOT / 'uninstall_server.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ServerUninstallTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='sslr-uninstall-test-')
        self.addCleanup(self.tmp.cleanup)
        self.p = Path(self.tmp.name)
        self.home = self.p / 'home'
        self.run = self.p / 'run'
        self.bin = self.p / 'bin'
        for d in (self.home, self.run, self.bin):
            d.mkdir()
        self.base = self.home / '.ssl-renewal'
        self.base.mkdir()
        self.manager = module.ServerUninstaller(self.home, self.run)
        for path, signature in self.manager.scripts.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('# fixture ' + signature + '\n')
        self.active_patch = mock.patch.object(self.manager, 'active_processes', return_value=[])
        self.active_patch.start()
        self.addCleanup(self.active_patch.stop)
        self.cron = self.p / 'crontab'
        self.other = '0 0 * * * %s --cron\n' % (self.home / '.acme.sh/acme.sh')
        self.other += '0 2 * * * echo %s\n' % (self.base / 'dynamic_ip_cert.sh')
        self.own = '*/5 * * * * %s %s >> /a/log 2>&1\n' % (self.base / 'dynamic_ip_cert.sh', self.base / 'dynamic-ip-v4.conf')
        self.own += '17 */6 * * * /bin/bash %s cron home >> /another/log 2>&1\n' % (self.base / 'remote/remote_ip_ssl.sh')
        self.cron.write_text(self.other + self.own)
        helper = self.bin / 'crontab'
        helper.write_text('''#!/usr/bin/env python3
import os,pathlib,sys
p=pathlib.Path(os.environ['TEST_CRON'])
if sys.argv[1]=='-l':
    if os.environ.get('TEST_CRON_READ_FAIL')=='1':
        print('Permission denied',file=sys.stderr);sys.exit(1)
    if not p.exists():
        print('no crontab for test',file=sys.stderr);sys.exit(1)
    print(p.read_text(),end='')
else:
    if os.environ.get('TEST_CRON_WRITE_FAIL')=='1':sys.exit(1)
    p.write_text(sys.stdin.read())
''')
        helper.chmod(0o700)
        env = mock.patch.dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ['PATH'], TEST_CRON=str(self.cron))
        env.start(); self.addCleanup(env.stop)
        (self.base / 'dynamic-ip-v4.conf').write_text('project config')
        (self.base / 'dynamic-ip-v4.state').write_text('45.77.170.45\n')
        (self.base / 'remote/devices').mkdir()
        (self.base / 'remote/devices/home.conf').write_text('remote config')
        (self.base / 'remote/certs').mkdir()
        (self.base / 'remote/certs/keep.key').write_text('remote cached key')
        (self.base / 'openwrt').mkdir()
        (self.base / 'openwrt/keep.conf').write_text('native router data')
        self.shared = self.home / '.acme.sh'
        self.shared.mkdir()
        (self.shared / 'acme.sh').write_text('shared acme client')
        (self.shared / 'account.conf').write_text('shared account')
        (self.home / 'cert.crt').write_text('server cert')
        (self.home / 'cert.key').write_text('server key')
        (self.home / '.ssh').mkdir()
        (self.home / '.ssh/key').write_text('ssh key')

    def snapshot_protected(self):
        return {str(p.relative_to(self.home)): p.read_bytes() for p in (
            self.shared / 'acme.sh', self.shared / 'account.conf', self.home / 'cert.crt',
            self.home / 'cert.key', self.home / '.ssh/key',
            self.base / 'openwrt/keep.conf', self.base / 'remote/certs/keep.key')}

    def test_keep_mode_removes_scripts_and_own_cron_only(self):
        before = self.snapshot_protected()
        backup = self.manager.execute(False, output=lambda _: None)
        self.assertEqual(before, self.snapshot_protected())
        self.assertEqual(self.other, self.cron.read_text())
        self.assertTrue((self.base / 'dynamic-ip-v4.conf').exists())
        self.assertTrue((self.base / 'remote/devices/home.conf').exists())
        self.assertTrue(self.manager.disabled.exists())
        self.assertFalse(self.manager.busy.exists())
        self.assertFalse((self.home / 'acme_3.0.sh').exists())
        self.assertTrue((backup / 'acme_3.0.sh').is_file())
        self.assertEqual(0o700, backup.stat().st_mode & 0o777)

    def test_purge_cleans_only_project_configuration_with_backup(self):
        before = self.snapshot_protected()
        backup = self.manager.execute(True, output=lambda _: None)
        self.assertEqual(before, self.snapshot_protected())
        self.assertFalse((self.base / 'dynamic-ip-v4.conf').exists())
        self.assertFalse((self.base / 'remote/devices/home.conf').exists())
        self.assertEqual('project config', (backup / '.ssl-renewal/dynamic-ip-v4.conf').read_text())
        self.assertEqual(self.other, self.cron.read_text())

    def test_unrelated_cron_mentions_and_commands_are_retained(self):
        lookalikes = [
            '* * * * * echo ' + str(self.base / 'dynamic_ip_cert.sh') + '\n',
            '* * * * * /another/tool # ' + str(self.base / 'remote/remote_ip_ssl.sh') + ' cron home\n',
            '* * * * * ' + str(self.base / 'dynamic_ip_cert.sh') + ' /unrelated.conf\n',
            'SHELL=/bin/bash\n', '# keep comment\n', '\n']
        for line in lookalikes:
            self.assertFalse(self.manager.owns_cron_line(line), line)
        self.assertEqual(''.join(lookalikes), self.manager.filter_cron(''.join(lookalikes)))

    def test_read_error_does_not_delete_or_clear_crontab(self):
        before = self.cron.read_bytes()
        with mock.patch.dict(os.environ, TEST_CRON_READ_FAIL='1'):
            with self.assertRaises(module.UninstallError):
                self.manager.execute(True)
        self.assertEqual(before, self.cron.read_bytes())
        self.assertTrue((self.home / 'acme_3.0.sh').exists())

    def test_write_error_preserves_scripts_and_configuration(self):
        with mock.patch.dict(os.environ, TEST_CRON_WRITE_FAIL='1'):
            with self.assertRaises(module.UninstallError):
                self.manager.execute(True)
        self.assertTrue((self.home / 'acme_3.0.sh').exists())
        self.assertTrue((self.base / 'dynamic-ip-v4.conf').exists())
        self.assertFalse(self.manager.busy.exists())
        self.assertFalse(self.manager.disabled.exists())

    def test_no_crontab_is_not_a_read_error(self):
        self.cron.unlink()
        self.assertEqual('', self.manager.read_cron())
        self.manager.execute(False, output=lambda _: None)
        self.assertFalse(self.cron.exists())

    def test_symlinked_program_is_rejected_without_following(self):
        target = self.p / 'unrelated'; target.write_text('keep')
        path = self.home / 'acme.sh'; path.unlink(); path.symlink_to(target)
        with self.assertRaises(module.UninstallError): self.manager.execute(True)
        self.assertEqual('keep', target.read_text())

    def test_symlinked_stop_markers_never_overwrite_target(self):
        target=self.p/'unrelated'; target.write_text('keep')
        self.manager.busy.symlink_to(target)
        with self.assertRaises(module.UninstallError): self.manager.execute(False)
        self.assertEqual('keep',target.read_text())
        self.assertTrue((self.home/'acme_3.0.sh').exists())

    def test_unknown_same_name_script_is_not_removed(self):
        (self.home / 'acme.sh').write_text('# not this project')
        with self.assertRaises(module.UninstallError): self.manager.execute(False)
        self.assertTrue((self.home / 'acme.sh').exists())

    def test_backup_symlink_is_rejected_before_mutation(self):
        target=self.p/'victim'; target.mkdir()
        (self.home / 'ssl-renewal-backups').symlink_to(target, target_is_directory=True)
        with self.assertRaises(module.UninstallError): self.manager.execute(True)
        self.assertTrue((self.home / 'acme.sh').exists())
        self.assertFalse(self.manager.disabled.exists())

    def test_active_operation_aborts_without_killing_or_removing(self):
        self.manager.active_processes.return_value=['12345']
        with self.assertRaises(module.UninstallError): self.manager.execute(True)
        self.assertTrue((self.home / 'acme_3.0.sh').exists())
        self.assertEqual(self.other+self.own,self.cron.read_text())

    def test_new_operation_after_stop_marker_aborts_safely(self):
        self.manager.active_processes.side_effect=[[],['54321']]
        with self.assertRaises(module.UninstallError): self.manager.execute(True)
        self.assertFalse(self.manager.busy.exists())
        self.assertTrue((self.home / 'acme_3.0.sh').exists())

    def test_cron_edit_between_reads_is_not_overwritten(self):
        actual=self.manager.read_cron
        count=[0]
        def changed():
            count[0]+=1
            if count[0]==2: self.cron.write_text('0 4 * * * /new/unrelated\n')
            return actual()
        with mock.patch.object(self.manager,'read_cron',side_effect=changed):
            with self.assertRaises(module.UninstallError): self.manager.execute(True)
        self.assertEqual('0 4 * * * /new/unrelated\n',self.cron.read_text())
        self.assertTrue((self.home / 'acme_3.0.sh').exists())

    def test_repeated_uninstall_is_safe(self):
        self.manager.execute(True,output=lambda _:None)
        self.manager.execute(True,output=lambda _:None)
        self.assertEqual(self.other,self.cron.read_text())
        self.assertTrue((self.shared/'account.conf').exists())

    def test_cancel_main_never_executes_uninstall(self):
        for choices in (['0'], ['1',''], ['2','wrong']):
            with mock.patch.object(module.os,'geteuid',return_value=0), \
                 mock.patch.object(module,'ServerUninstaller',return_value=self.manager), \
                 mock.patch.object(self.manager,'plan',return_value=[]), \
                 mock.patch('builtins.input',side_effect=choices), \
                 mock.patch('builtins.print'), \
                 mock.patch.object(self.manager,'execute') as execute:
                self.assertEqual(2,module.main())
                execute.assert_not_called()

    def test_dynamic_wrapper_obeys_uninstall_stop_marker(self):
        self.manager.disabled.touch()
        result=subprocess.run(['bash',str(ROOT/'dynamic_ip_cert.sh'),str(self.base/'dynamic-ip-v4.conf')],
                              text=True,capture_output=True,timeout=10)
        self.assertEqual(0,result.returncode,result.stderr)
        self.assertIn('跳过任务',result.stdout)

    def test_legacy_remote_obeys_stop_marker_without_ssh(self):
        self.manager.disabled.touch()
        result=subprocess.run(['bash',str(ROOT/'remote_ip_ssl.sh'),'cron','home'],
                              env=dict(os.environ,SSL_RENEWAL_REMOTE_BASE=str(self.base/'remote')),
                              text=True,capture_output=True,timeout=10)
        self.assertEqual(0,result.returncode,result.stderr)
        self.assertIn('跳过远程任务',result.stdout)

    def test_bootstrap_reinstalls_uninstaller_and_clears_only_own_marker(self):
        source=(ROOT/'acme.sh').read_text()
        self.assertIn('install -m 700 "$DOWNLOAD_DIR/repo/uninstall_server.py" /root/uninstall_server.py',source)
        self.assertIn('rm -f /root/.ssl-renewal/server.uninstalled',source)
        self.assertNotIn('rm -rf /root/.acme.sh',source)


if __name__ == '__main__':
    unittest.main(verbosity=2)
