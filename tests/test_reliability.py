#!/usr/bin/env python3
"""Regression cases from the reliability review; real TLS, isolated OS/CA adapters."""
import fcntl
import json
import os
from pathlib import Path
import signal
import subprocess
import unittest

import test_openwrt_local as fixtures
import test_smart_menu as server_fixtures


class OpenWrtReliabilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.OpenWrtLocalTests.setUpClass()

    @classmethod
    def tearDownClass(cls):
        fixtures.OpenWrtLocalTests.tearDownClass()

    def setUp(self):
        self.f = fixtures.OpenWrtLocalTests(methodName='runTest')
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)

    def setup_input(self, reload='false', reconfigure=True, uhttpd=False):
        return ('1\n' + ('RECONFIGURE\n' if reconfigure else '') +
                '1\nwan\n\ntest@example.com\n\n' +
                ('2\n\n' if uhttpd else '1\n' + reload + '\n') + 'yes\n')

    def old_state(self):
        self.f.cli('check', '4')
        self.f.shell('ow_cron')
        return {p: p.read_bytes() for p in (self.f.base/'v4.conf', self.f.base/'v4.ip',
                self.f.base/'v4.deployed', self.f.p/'crontab')}

    def assert_preserved(self, snapshot):
        for path, content in snapshot.items():
            self.assertEqual(content, path.read_bytes(), str(path))

    def test_bad_reconfiguration_restores_config_cert_and_job(self):
        before = self.old_state()
        link = os.readlink(self.f.base/'certs/v4/current')
        cert = (self.f.base/'certs/v4/current/fullchain.pem').read_bytes()
        result = self.f.cli('setup', input_text=self.setup_input(), expected=None)
        self.assertNotEqual(0, result.returncode)
        self.assert_preserved(before)
        self.assertEqual(link, os.readlink(self.f.base/'certs/v4/current'))
        self.assertEqual(cert, (self.f.base/'certs/v4/current/fullchain.pem').read_bytes())
        self.f.cli('check', '4')  # Previous working configuration still works.
        self.assertEqual(1, len(self.f.calls('fake-acme-tool', '--issue')))

    def test_failed_first_setup_does_not_enable_job_or_publish_config(self):
        (self.f.base/'v4.conf').unlink()
        unrelated = '0 2 * * * /bin/backup\n'
        (self.f.p/'crontab').write_text(unrelated)
        result = self.f.cli('setup', input_text=self.setup_input(reconfigure=False), expected=None)
        self.assertNotEqual(0, result.returncode)
        self.assertFalse((self.f.base/'v4.conf').exists())
        self.assertFalse((self.f.base/'v4.ip').exists())
        self.assertEqual(unrelated, (self.f.p/'crontab').read_text())
        self.assertTrue((self.f.run/'v4.setup-error').exists())

    def test_cron_failure_after_trial_restores_old_configuration(self):
        before = self.old_state()
        link = os.readlink(self.f.base/'certs/v4/current')
        result = self.f.cli('setup', input_text=self.setup_input(reload=':'),
                            env={'MOCK_CRON_RC': '1'}, expected=None)
        self.assertNotEqual(0, result.returncode)
        self.assert_preserved(before)
        self.assertEqual(link, os.readlink(self.f.base/'certs/v4/current'))

    def test_cron_failure_after_tls_trial_restores_uci_and_certificate(self):
        self.f.config(DEPLOY='uhttpd')
        before = self.old_state()
        old_uci = (self.f.p/'uci.json').read_bytes()
        link = os.readlink(self.f.base/'certs/v4/current')
        self.f.network(ip='1.1.1.1')
        result = self.f.cli('setup', input_text=self.setup_input(uhttpd=True),
                            env={'MOCK_CRON_RC': '1'}, expected=None)
        self.assertNotEqual(0, result.returncode)
        self.assert_preserved(before)
        self.assertEqual(link, os.readlink(self.f.base/'certs/v4/current'))
        self.assertEqual(old_uci, (self.f.p/'uci.json').read_bytes())
        self.f.shell('ow_paths 4; UHTTPD_SECTION=main; ow_verify_uhttpd "$CERTROOT/current/fullchain.pem" "45.77.170.45"')

    def test_successful_reconfiguration_reuses_valid_certificate(self):
        self.old_state()
        self.f.cli('setup', input_text=self.setup_input(reload=':'))
        self.assertIn('RELOAD_CMD=:', (self.f.base/'v4.conf').read_text())
        self.assertEqual(1, len(self.f.calls('fake-acme-tool', '--issue')))
        self.assertFalse((self.f.run/'v4.setup-error').exists())

    def test_no_https_listener_rejected_before_dependencies_or_ca(self):
        (self.f.base/'v4.conf').unlink()
        db = self.f.original_uci.copy(); db.pop('uhttpd.main.listen_https')
        (self.f.p/'uci.json').write_text(json.dumps(db))
        result = self.f.cli('setup', input_text=self.setup_input(reconfigure=False, uhttpd=True), expected=None)
        self.assertNotEqual(0, result.returncode)
        self.assertIn('listen_https', result.stdout)
        self.assertFalse(self.f.calls('opkg'))
        self.assertFalse(self.f.calls('fake-acme-tool'))
        self.assertFalse(self.f.calls('uci', 'set'))

    def test_pending_uci_changes_rejected_without_commit(self):
        self.f.config(DEPLOY='uhttpd')
        result = self.f.cli('check', '4', env={'MOCK_UCI_CHANGES': 'uhttpd.main.home=/pending\n'}, expected=None)
        self.assertNotEqual(0, result.returncode)
        self.assertFalse(self.f.calls('uci', 'commit'))
        self.assertFalse(self.f.calls('fake-acme-tool'))

    def test_missing_tls_library_does_not_request_certificate(self):
        self.f.config(DEPLOY='uhttpd')
        (self.f.p/'tls-library').unlink()
        result = self.f.cli('check', '4', expected=None)
        self.assertNotEqual(0, result.returncode)
        self.assertFalse(self.f.calls('fake-acme-tool'))

    def test_restart_success_without_listener_is_not_deploy_success(self):
        self.f.config(DEPLOY='uhttpd')
        result = self.f.cli('check', '4', env={'MOCK_NO_TLS_START': '1'}, expected=None)
        self.assertNotEqual(0, result.returncode)
        self.assertFalse((self.f.base/'v4.ip').exists())
        self.assertFalse((self.f.base/'v4.deployed').exists())
        self.assertEqual(self.f.original_uci, json.loads((self.f.p/'uci.json').read_text()))

    def test_stale_real_tls_certificate_triggers_rollback(self):
        self.f.config(DEPLOY='uhttpd')
        self.f.cli('check', '4')
        link = os.readlink(self.f.base/'certs/v4/current')
        self.f.network(ip='1.1.1.1')
        result = self.f.cli('check', '4', env={'MOCK_NO_TLS_START': '1'}, expected=None)
        self.assertNotEqual(0, result.returncode)
        self.assertEqual(link, os.readlink(self.f.base/'certs/v4/current'))
        self.assertEqual(fixtures.V4, (self.f.base/'v4.ip').read_text().strip())

    def test_reload_background_child_does_not_keep_operation_lock(self):
        pidfile = self.f.p/'hook.pid'
        self.f.config(RELOAD_CMD='sleep 20 >/dev/null 2>&1 & echo $! > "$FIXTURE/hook.pid"')
        def cleanup():
            if pidfile.exists():
                try: os.kill(int(pidfile.read_text()), signal.SIGTERM)
                except ProcessLookupError: pass
        self.addCleanup(cleanup)
        self.f.cli('check', '4')
        self.assertTrue(pidfile.exists())
        with (self.f.run/'operation.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        result = self.f.cli('check', '4')
        self.assertNotIn('已有证书操作', result.stdout)

    def test_hook_timeout_releases_lock_and_preserves_old_certificate(self):
        before = self.old_state()
        link = os.readlink(self.f.base/'certs/v4/current')
        result = self.f.cli('setup', input_text=self.setup_input(reload='sleep 10'),
                            env={'SSL_RENEWAL_OPENWRT_RELOAD_TIMEOUT': '1'}, expected=None)
        self.assertNotEqual(0, result.returncode)
        self.assert_preserved(before)
        self.assertEqual(link, os.readlink(self.f.base/'certs/v4/current'))
        with (self.f.run/'operation.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_cron_comment_does_not_delete_another_job(self):
        line = '0 2 * * * /backup # ssl-renewal-openwrt-local documentation only\n'
        (self.f.p/'crontab').write_text(line)
        self.f.shell('ow_cron; ow_cron')
        current = (self.f.p/'crontab').read_text()
        self.assertIn(line, current)
        self.assertEqual(1, current.count('check-all'))

    def test_concurrent_crontab_change_is_preserved(self):
        original = '0 2 * * * /old-backup\n'
        changed = '0 3 * * * /new-backup\n'
        cron = self.f.p/'crontab'; cron.write_text(original)
        result = self.f.shell('awk() { command awk "$@"; printf "0 3 * * * /new-backup\\n" >> "$OW_CRONTAB"; }; ow_cron', expected=None)
        self.assertNotEqual(0, result.returncode)
        self.assertEqual(original + changed, cron.read_text())

    def test_cgnat_stops_before_email_packages_and_ca(self):
        (self.f.base/'v4.conf').unlink()
        self.f.network(ip='100.64.2.164')
        result = self.f.cli('setup', input_text='1\n1\nwan\n\n', expected=None)
        self.assertNotEqual(0, result.returncode)
        self.assertIn('100.64.2.164', result.stdout)
        self.assertIn('CGNAT', result.stdout)
        self.assertNotIn('电子邮件地址', result.stdout)
        self.assertFalse(self.f.calls('opkg'))
        self.assertFalse(self.f.calls('fake-acme-tool'))

    def test_ula_is_not_treated_as_public_ipv6(self):
        self.f.network(v6='fd23:fb18:6063::1')
        result = self.f.cli('setup', input_text='2\n1\nwan6\n\n', expected=None)
        self.assertNotEqual(0, result.returncode)
        self.assertIn('ULA', result.stdout)
        self.assertFalse(self.f.calls('opkg'))

    def test_status_reports_real_job_dates_and_tls_without_mutating_service(self):
        self.f.config(DEPLOY='uhttpd')
        self.f.cli('check', '4'); self.f.shell('ow_cron')
        before_uci = (self.f.p/'uci.json').read_bytes()
        restarts = len(self.f.calls('uhttpd', 'restart'))
        result = self.f.cli('status')
        for text in ('定时任务：存在', 'cron 服务：运行中', '当前接口地址', '剩余有效期', '上次成功部署', 'HTTPS 已加载目标证书'):
            self.assertIn(text, result.stdout)
        self.assertEqual(restarts, len(self.f.calls('uhttpd', 'restart')))
        self.assertEqual(before_uci, (self.f.p/'uci.json').read_bytes())


class ServerReliabilityTests(unittest.TestCase):
    def setUp(self):
        self.f = server_fixtures.SmartMenuTests(methodName='runTest')
        self.f.setUp(); self.addCleanup(self.f.doCleanups)

    def issue(self, command):
        return self.f.shell('ACME_BIN="$TEST_DIR/bin/fake-acme"; CERT_KIND=ip; IDENTIFIER=45.77.170.45; IP_VERSION=4; '
                            'CA_SERVER=letsencrypt; CERT_PATH="$TEST_DIR/cert"; KEY_PATH="$TEST_DIR/key"; '
                            + command + '; issue_static_certificate')

    def test_configured_reload_is_passed_to_acme_install(self):
        self.issue('RELOAD_CMD="systemctl reload nginx"')
        log = (self.f.base/'acme.log').read_text()
        self.assertIn('--reloadcmd systemctl reload nginx', log)
        self.assertIn('--ecc', log)
        self.assertIn('--keylength ec-256', log)

    def test_save_only_explicitly_clears_old_hook(self):
        self.issue('RELOAD_CMD=""')
        self.assertIn('--reloadcmd :', (self.f.base/'acme.log').read_text())

    def test_reload_menu_uses_simple_labels(self):
        result = self.f.shell('select_server_deployment', '0\n', expected=None)
        self.assertIn('1）只保存证书【默认】', result.stdout)
        self.assertIn('2）保存证书并自动重载服务', result.stdout)
        self.assertIn('不自动重载网站/服务', result.stdout)
        self.assertIn('适合 Nginx/Apache', result.stdout)
        self.assertNotIn('清除此证书原有的自动重载设置', result.stdout)

    def test_reload_prompt_requires_confirmation(self):
        result = self.f.shell('select_server_deployment; printf "HOOK=%s\\n" "$RELOAD_CMD"',
                              '2\nsystemctl reload nginx\nno\n1\n')
        self.assertIn('未确认', result.stdout)
        self.assertIn('HOOK=\n', result.stdout)
        self.assertFalse((self.f.base/'acme.log').exists())

    def test_reload_prompt_accepts_explicit_choice(self):
        result = self.f.shell('select_server_deployment; printf "HOOK=%s\\n" "$RELOAD_CMD"',
                              '2\nsystemctl reload nginx\nyes\n')
        self.assertIn('HOOK=systemctl reload nginx', result.stdout)

    def test_buypass_disabled_without_changing_other_ca_numbers(self):
        result = self.f.shell('select_domain_ca; echo "CA=$CA_SERVER"', '2\n3\n')
        self.assertIn('停止 TLS/SSL', result.stdout)
        self.assertIn('CA=zerossl', result.stdout)
        self.assertFalse((self.f.base/'acme.log').exists())

    def test_existing_certificate_default_choice_reuses_without_validation(self):
        cert = self.f.base / 'existing.crt'
        key = self.f.base / 'existing.key'
        cert.write_text('fixture-cert')
        key.write_text('fixture-key')
        body = (
            'CERT_KIND=ip; IDENTIFIER=45.77.170.45; CHALLENGE_MODE=webroot; '
            'CERT_PATH="$TEST_DIR/existing.crt"; KEY_PATH="$TEST_DIR/existing.key"; '
            'existing_certificate_valid() { return 0; }; '
            'select_existing_certificate_action; '
            'printf "REUSE=%s FORCE=%s MODE=%s\\n" "$REUSE_EXISTING_CERT" "$FORCE_FRESH_ISSUE" "$CERT_RESULT_MODE"'
        )
        result = self.f.shell(body, '\n')
        self.assertIn('直接使用本地现有证书', result.stdout)
        self.assertIn('REUSE=1 FORCE=0 MODE=reused', result.stdout)
        self.assertFalse((self.f.base/'acme.log').exists())

    def test_existing_certificate_force_choice_uses_selected_webroot(self):
        (self.f.base/'existing.crt').write_text('fixture-cert')
        (self.f.base/'existing.key').write_text('fixture-key')
        body = (
            'ACME_BIN="$TEST_DIR/bin/fake-acme"; CERT_KIND=ip; IDENTIFIER=45.77.170.45; IP_VERSION=4; '
            'CA_SERVER=letsencrypt; CHALLENGE_MODE=webroot; WEBROOT_PATH="$TEST_WEBROOT"; '
            'CERT_PATH="$TEST_DIR/existing.crt"; KEY_PATH="$TEST_DIR/existing.key"; RELOAD_CMD=""; '
            'existing_certificate_valid() { return 0; }; '
            'select_existing_certificate_action; issue_static_certificate'
        )
        result = self.f.shell(body, '2\n')
        self.assertIn('强制重新签发', result.stdout)
        issue = (self.f.base/'acme.log').read_text().splitlines()[0]
        self.assertIn('--force', issue)
        self.assertIn('-w ' + str(self.f.webroot), issue)

    def test_reuse_existing_save_only_skips_issue_but_syncs_install_settings(self):
        body = (
            'ACME_BIN="$TEST_DIR/bin/fake-acme"; CERT_KIND=ip; IDENTIFIER=45.77.170.45; IP_VERSION=4; '
            'CA_SERVER=letsencrypt; CHALLENGE_MODE=webroot; WEBROOT_PATH="$TEST_WEBROOT"; '
            'CERT_PATH="$TEST_DIR/cert"; KEY_PATH="$TEST_DIR/key"; RELOAD_CMD=""; '
            'REUSE_EXISTING_CERT=1; CERT_RESULT_MODE=reused; issue_static_certificate'
        )
        result = self.f.shell(body)
        self.assertIn('不向 CA 发起签发请求', result.stdout)
        log = (self.f.base/'acme.log').read_text()
        self.assertNotIn('--issue', log)
        self.assertIn('--install-cert', log)
        self.assertIn('--reloadcmd :', log)



if __name__ == '__main__':
    unittest.main(verbosity=2)
