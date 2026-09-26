#!/usr/bin/env python3
"""Offline regression tests: no CA requests, package installs or host changes."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
MAIN = ROOT / 'acme_3.0.sh'
V4 = '45.77.170.45'
V6 = '2606:4700:4700::1111'


class SmartMenuTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='ssl-menu-test-')
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.bin = self.base / 'bin'
        self.bin.mkdir()
        self.webroot = self.base / 'website with spaces'
        self.webroot.mkdir()
        self.env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ['PATH'],
                        MOCK_IP4=V4, MOCK_IP6=V6, MOCK_SS='', MOCK_SS_FAIL='0',
                        MOCK_SS_P_FAIL='0', MOCK_PRIMARY_BAD='', MOCK_CURL_FAIL='0',
                        MOCK_CURL_LOG=str(self.base / 'curl.log'),
                        TEST_DIR=str(self.base), TEST_WEBROOT=str(self.webroot),
                        MOCK_ACME_RC='0', MOCK_INSTALL_RC='0',
                        PYTHONDONTWRITEBYTECODE='1')
        self.write_command('curl', '''#!/usr/bin/env python3
import os, sys
args = sys.argv[1:]
assert args[0] == '-q', args
assert args[args.index('--noproxy') + 1] == '*', args
assert args[args.index('--proxy') + 1] == '', args
assert args[args.index('--proto') + 1] == '=https', args
assert args[args.index('--max-time') + 1] == '5', args
url = args[-1]
with open(os.environ['MOCK_CURL_LOG'], 'a') as f:
    f.write(url + '\\n')
if os.environ.get('MOCK_CURL_FAIL') == '1':
    sys.exit(28)
if 'ipw.cn' in url and os.environ.get('MOCK_PRIMARY_BAD'):
    print(os.environ['MOCK_PRIMARY_BAD'])
    sys.exit(0)
value = os.environ['MOCK_IP4' if '-4' in args else 'MOCK_IP6']
if value:
    print(value)
else:
    sys.exit(7)
''')
        self.write_command('ss', '''#!/usr/bin/env python3
import os, sys
if os.environ['MOCK_SS_FAIL'] == '1':
    sys.exit(1)
if os.environ['MOCK_SS_P_FAIL'] == '1' and 'p' in sys.argv[1]:
    sys.exit(1)
print(os.environ['MOCK_SS'], end='')
''')
        self.write_command('fake-acme', '''#!/bin/bash
printf '%s\\n' "$*" >> "$TEST_DIR/acme.log"
case "$1" in
    --issue) exit "$MOCK_ACME_RC" ;;
    --install-cert) exit "$MOCK_INSTALL_RC" ;;
    *) echo 'Unexpected ACME operation' >&2; exit 91 ;;
esac
''')
        # Fail loudly if a menu regression attempts host administration.
        for command in ('apt-get', 'yum', 'dnf', 'systemctl', 'service', 'ufw',
                        'firewall-cmd', 'ssh', 'crontab'):
            self.write_command(command, '#!/bin/sh\necho "UNEXPECTED_HOST_CHANGE" >&2\nexit 99\n')

    def write_command(self, name, content):
        path = self.bin / name
        path.write_text(content)
        path.chmod(0o700)

    def shell(self, body, input_text='', env=None, expected=0):
        current = dict(self.env)
        current.update(env or {})
        result = subprocess.run(
            ['bash', '--noprofile', '--norc', '-c', 'source "$1";\n' + body,
             'smart-menu-test', str(MAIN)], input=input_text, text=True,
            capture_output=True, env=current, timeout=20)
        self.assertNotIn('UNEXPECTED_HOST_CHANGE', result.stdout + result.stderr)
        if expected is not None:
            self.assertEqual(expected, result.returncode, result.stdout + result.stderr)
        return result

    @staticmethod
    def listener(port, program='nginx', address='0.0.0.0'):
        return 'LISTEN 0 128 {}:{} 0.0.0.0:* users:(("{}",pid=42,fd=6))\n'.format(address, port, program)

    def test_all_shell_syntax(self):
        for path in ROOT.glob('*.sh'):
            with self.subTest(path=path.name):
                subprocess.run(['bash', '-n', str(path)], check=True, capture_output=True)

    def test_source_has_no_deployment_side_effects(self):
        result = self.shell('echo SOURCED')
        self.assertEqual('SOURCED\n', result.stdout)
        self.assertFalse((self.base / 'curl.log').exists())

    def test_validate_ipv4(self):
        result = self.shell('validate_public_ip " 45.77.170.45 "; echo "$IP_VERSION|$IP_CANONICAL"')
        self.assertEqual('4|' + V4 + '\n', result.stdout)

    def test_validate_ipv6_normalization_and_brackets(self):
        result = self.shell('validate_public_ip " [2606:4700:4700:0:0:0:0:1111] "; echo "$IP_VERSION|$IP_CANONICAL"')
        self.assertEqual('6|' + V6 + '\n', result.stdout)

    def test_reject_nonpublic_and_malformed_inputs(self):
        invalid = ['192.168.2.1', '100.64.0.1', '127.0.0.1', '0.0.0.0',
                   '224.0.0.1', '239.255.255.1', '240.0.0.1', '192.0.2.1',
                   '::1', 'fc00::1', 'fe80::1', 'ff02::1', '2001:db8::1',
                   '::ffff:45.77.170.45', '2606:4700::1111%eth0',
                   'https://45.77.170.45', '45.77.170.45:443', '45.77.170.45/24',
                   '045.77.170.45', '45.77. 170.45', '45.77.170.45\n1.1.1.1',
                   'example.com', '$(touch /tmp/never)', '[45.77.170.45]', '']
        for value in invalid:
            with self.subTest(value=value):
                self.shell('if validate_public_ip "$CANDIDATE"; then exit 90; fi',
                           env={'CANDIDATE': value})

    def test_failed_validation_clears_stale_state(self):
        self.shell('IP_VERSION=4; IP_CANONICAL=old; '
                   'if validate_public_ip invalid; then exit 90; fi; '
                   'test -z "$IP_CANONICAL"; test -z "$IP_VERSION"')

    def test_discovery_fallback_from_html(self):
        result = self.shell('detect_public_ips; echo "RESULT=$DETECTED_IPV4|$DETECTED_IPV6"',
                            env={'MOCK_PRIMARY_BAD': '<html>bad gateway</html>'})
        self.assertIn('RESULT=' + V4 + '|' + V6, result.stdout)
        self.assertIn('api4.ipify.org', (self.base / 'curl.log').read_text())

    def test_discovery_fallback_from_private_address(self):
        result = self.shell('detect_public_ips; echo "RESULT=$DETECTED_IPV4"',
                            env={'MOCK_PRIMARY_BAD': '192.168.2.1'})
        self.assertIn('RESULT=' + V4, result.stdout)

    def test_discovery_rejects_wrong_family(self):
        result = self.shell('detect_public_ips; echo "RESULT=$DETECTED_IPV6"',
                            env={'MOCK_IP6': V4})
        self.assertTrue(result.stdout.endswith('RESULT=\n'))

    def test_default_ipv4_selection(self):
        result = self.shell('select_public_ip; echo "RESULT=$IDENTIFIER|$IP_VERSION"', '\n')
        self.assertIn('RESULT=' + V4 + '|4', result.stdout)

    def test_ipv6_only_default(self):
        result = self.shell('select_public_ip; echo "RESULT=$IDENTIFIER|$IP_VERSION"', '\n',
                            env={'MOCK_IP4': ''})
        self.assertIn('RESULT=' + V6 + '|6', result.stdout)

    def test_manual_fallback_when_all_probes_fail(self):
        result = self.shell('select_public_ip; echo "RESULT=$IDENTIFIER"', '\n' + V4 + '\n',
                            env={'MOCK_CURL_FAIL': '1'})
        self.assertIn('RESULT=' + V4, result.stdout)

    def test_unavailable_family_and_invalid_manual_retry(self):
        result = self.shell('select_public_ip; echo "RESULT=$IDENTIFIER"',
                            '2\n3\n192.168.2.1\n3\n' + V4 + '\n', env={'MOCK_IP6': ''})
        self.assertIn('当前没有可用地址', result.stdout)
        self.assertIn('不能使用私网', result.stdout)
        self.assertIn('RESULT=' + V4, result.stdout)

    def test_redetection(self):
        self.shell('select_public_ip', '4\n1\n')
        self.assertGreaterEqual(len((self.base / 'curl.log').read_text().splitlines()), 4)

    def test_ip_selection_cancel_and_eof(self):
        for value in ('0\n', ''):
            with self.subTest(value=value):
                self.shell('if select_public_ip; then exit 90; fi', value)

    def test_proxies_disabled_for_detection(self):
        result = self.shell('select_public_ip; echo "RESULT=$IDENTIFIER"', '\n',
                            env={'https_proxy': 'http://127.0.0.1:9',
                                 'ALL_PROXY': 'socks5://127.0.0.1:9'})
        # The fake curl asserts the actual override arguments on every invocation.
        self.assertIn('RESULT=' + V4, result.stdout)

    def test_port_recommendation_matrix(self):
        cases = [('', 'free|free|1'),
                 (self.listener(443), 'free|busy|1'),
                 (self.listener(80), 'busy|free|2'),
                 (self.listener(80) + self.listener(443), 'busy|busy|2'),
                 (self.listener(80, 'other'), 'busy|free|3'),
                 (self.listener(80, 'other') + self.listener(443), 'busy|busy|')]
        for listeners, expected in cases:
            with self.subTest(expected=expected):
                result = self.shell('refresh_port_status; recommend_challenge; '
                                    'echo "$PORT80_STATE|$PORT443_STATE|$RECOMMENDED_CHALLENGE"',
                                    env={'MOCK_SS': listeners})
                self.assertEqual(expected + '\n', result.stdout)

    def test_ipv6_listener_and_nonmatching_ports(self):
        result = self.shell('refresh_port_status; echo "$PORT80_STATE|$PORT443_STATE"',
                            env={'MOCK_SS': self.listener(80, address='[::]') + self.listener(8443)})
        self.assertEqual('busy|free\n', result.stdout)
        result = self.shell('refresh_port_status; echo "$PORT80_STATE|$PORT443_STATE"',
                            env={'MOCK_SS': self.listener(8080) + self.listener(8443)})
        self.assertEqual('free|free\n', result.stdout)

    def test_unknown_port_status_not_free(self):
        result = self.shell('refresh_port_status; recommend_challenge; '
                            'echo "$PORT80_STATE|$PORT443_STATE|$RECOMMENDED_CHALLENGE"',
                            env={'MOCK_SS_FAIL': '1'})
        self.assertEqual('unknown|unknown|\n', result.stdout)

    def test_ss_fallback_without_process_details(self):
        result = self.shell('refresh_port_status; echo "$PORT80_STATE"',
                            env={'MOCK_SS_P_FAIL': '1', 'MOCK_SS': self.listener(80)})
        self.assertEqual('busy\n', result.stdout)

    def test_default_standalone(self):
        result = self.shell('select_ip_challenge; echo "RESULT=$CHALLENGE_MODE|$VALIDATION_PORT"', '\n')
        self.assertIn('RESULT=standalone|80', result.stdout)

    def test_webroot_recommendation_preserves_path_spaces(self):
        result = self.shell('select_ip_challenge; echo "RESULT=$CHALLENGE_MODE|$WEBROOT_PATH"',
                            '\n' + str(self.webroot) + '\n', env={'MOCK_SS': self.listener(80)})
        self.assertIn('RESULT=webroot|' + str(self.webroot), result.stdout)

    def test_invalid_webroot_does_not_get_created(self):
        nonexistent = self.base / 'do-not-create'
        result = self.shell('select_ip_challenge; echo "RESULT=$CHALLENGE_MODE"',
                            '2\n' + str(nonexistent) + '\n1\n')
        self.assertFalse(nonexistent.exists())
        self.assertIn('RESULT=standalone', result.stdout)

    def test_occupied_standalone_returns_to_menu(self):
        result = self.shell('select_ip_challenge; echo "RESULT=$CHALLENGE_MODE"',
                            '1\n3\n', env={'MOCK_SS': self.listener(80, 'other')})
        self.assertIn('不会停止现有服务', result.stdout)
        self.assertIn('RESULT=alpn', result.stdout)

    def test_challenge_cancel_and_no_unsafe_default(self):
        result = self.shell('if select_ip_challenge; then exit 90; fi', '\n0\n',
                            env={'MOCK_SS_FAIL': '1'})
        self.assertIn('无法可靠推荐', result.stdout)

    def test_preissue_recheck_catches_new_listener(self):
        result = self.shell('CHALLENGE_MODE=standalone; VALIDATION_PORT=80; check_challenge_port',
                            env={'MOCK_SS': self.listener(80)}, expected=None)
        self.assertNotEqual(0, result.returncode)
        self.assertIn('不停止现有服务', result.stdout)

    def test_safe_firewall_default_and_confirmation(self):
        result = self.shell('select_firewall_action; echo "RESULT=$FIREWALL_OPTION"', '\n')
        self.assertIn('RESULT=3', result.stdout)
        result = self.shell('select_firewall_action; echo "RESULT=$FIREWALL_OPTION"', '1\nno\n\n')
        self.assertIn('RESULT=3', result.stdout)

    def test_final_request_cancel(self):
        result = self.shell('IDENTIFIER=45.77.170.45; IP_VERSION=4; IP_SELECTION_MODE=manual; '
                            'if confirm_ip_request; then exit 90; fi', 'n\n')
        self.assertIn('已取消', result.stdout)

    def test_repeated_issue_skip_installs_without_remove(self):
        result = self.shell('ACME_BIN="$TEST_DIR/bin/fake-acme"; CERT_KIND=ip; '
                            'IDENTIFIER=45.77.170.45; IP_VERSION=4; '
                            'KEY_PATH="$TEST_DIR/old.key"; CERT_PATH="$TEST_DIR/old.crt"; '
                            'issue_static_certificate', env={'MOCK_ACME_RC': '2'})
        self.assertIn('跳过了重复签发', result.stdout)
        log = (self.base / 'acme.log').read_text()
        self.assertIn('--install-cert', log)
        self.assertNotIn('--remove', log)
        self.assertNotIn('--force', log)

    def test_issue_failure_keeps_existing_files(self):
        (self.base / 'old.key').write_text('existing-key')
        (self.base / 'old.crt').write_text('existing-cert')
        result = self.shell('ACME_BIN="$TEST_DIR/bin/fake-acme"; CERT_KIND=ip; '
                            'IDENTIFIER=45.77.170.45; IP_VERSION=4; '
                            'KEY_PATH="$TEST_DIR/old.key"; CERT_PATH="$TEST_DIR/old.crt"; '
                            'issue_static_certificate', env={'MOCK_ACME_RC': '1'}, expected=None)
        self.assertNotEqual(0, result.returncode)
        self.assertEqual('existing-key', (self.base / 'old.key').read_text())
        self.assertEqual('existing-cert', (self.base / 'old.crt').read_text())
        self.assertNotIn('--remove', (self.base / 'acme.log').read_text())

    def test_domain_issuance_command_preserved(self):
        self.shell('ACME_BIN="$TEST_DIR/bin/fake-acme"; CERT_KIND=domain; '
                   'IDENTIFIER=example.com; CA_SERVER=letsencrypt; '
                   'KEY_PATH="$TEST_DIR/key"; CERT_PATH="$TEST_DIR/crt"; issue_static_certificate')
        first = (self.base / 'acme.log').read_text().splitlines()[0]
        self.assertIn('--standalone', first)
        self.assertNotIn('shortlived', first)

    def test_full_fixed_ip_menu_wiring(self):
        # Exercise main's real prompt order; replace effects, not menu logic.
        body = '''
require_root() { :; }
install_dependencies() { DEPENDENCIES_READY=1; }
configure_firewall() { echo "FIREWALL_CHOICE=$FIREWALL_OPTION"; }
ensure_acme() { :; }
register_account() { :; }
show_certificate_info() { echo "RESULT=$IDENTIFIER|$IP_VERSION|$CHALLENGE_MODE"; }
ACME_BIN="$TEST_DIR/bin/fake-acme"
main
'''
        result = self.shell(body, '2\n\ntest@example.com\n\ny\n\n')
        self.assertIn('RESULT=' + V4 + '|4|standalone', result.stdout)
        self.assertIn('FIREWALL_CHOICE=3', result.stdout)
        self.assertIn('--cert-profile shortlived --days 3', (self.base / 'acme.log').read_text())

    def test_full_fixed_ip_menu_cancel_before_issuance(self):
        body = '''
require_root() { :; }
install_dependencies() { DEPENDENCIES_READY=1; }
ACME_BIN="$TEST_DIR/bin/fake-acme"
main
'''
        result = self.shell(body, '2\n\ntest@example.com\n\nn\n')
        self.assertIn('已取消', result.stdout)
        self.assertFalse((self.base / 'acme.log').exists())

    def navigation(self, body='', input_text=''):
        return self.shell('''
require_root() { :; }
sleep() { :; }
DYNAMIC_DIR="$TEST_DIR/dynamic"
DYNAMIC_RUNNER="$DYNAMIC_DIR/dynamic_ip_cert.sh"
REMOTE_DIR="$TEST_DIR/remote"
REMOTE_RUNNER="$REMOTE_DIR/remote_ip_ssl.sh"
''' + body + '\nmain', input_text)

    def dynamic_fixture(self, families=(4,)):
        directory = self.base / 'dynamic'
        directory.mkdir(exist_ok=True)
        for family in families:
            (directory / ('dynamic-ip-v%d.conf' % family)).write_text('''
STATE_FILE="$TEST_DIR/dynamic/dynamic-ip-v%s.state"
CERT_PATH="$TEST_DIR/kept.crt"
KEY_PATH="$TEST_DIR/kept.key"
CHALLENGE_MODE=webroot
''' % family)
            (directory / ('dynamic-ip-v%d.state' % family)).write_text(V4 + '\n')
            (directory / ('dynamic-ip-v%d.log' % family)).write_text('old-log\n')
        runner = directory / 'dynamic_ip_cert.sh'
        runner.write_text('#!/bin/bash\nprintf "CHECKED=%s\\n" "$1"\n')
        runner.chmod(0o700)
        return directory

    def test_main_exit_and_eof_do_not_deploy(self):
        for text in ('6\n', ''):
            with self.subTest(text=text):
                result = self.navigation(input_text=text)
                self.assertIn('4）远程设备 IP 证书', result.stdout)
                self.assertNotIn('4）本机动态 IP SSL 管理', result.stdout)
                self.assertFalse((self.base / 'curl.log').exists())

    def test_dynamic_submenu_returns_without_falling_into_issuance(self):
        result = self.navigation(input_text='3\n0\n6\n')
        self.assertIn('1）开通 / 重新配置', result.stdout)
        self.assertIn('IPv4：未配置；IPv6：未配置', result.stdout)
        self.assertEqual(2, result.stdout.count('SSL证书管理菜单'))
        self.assertFalse((self.base / 'curl.log').exists())

    def test_dynamic_navigation_handles_invalid_input_and_eof(self):
        for text in ('3\n', '3\nwrong\n0\n6\n', 'wrong\n6\n'):
            with self.subTest(text=text):
                self.navigation(input_text=text)
        self.assertFalse((self.base / 'curl.log').exists())

    def test_empty_dynamic_status_does_not_require_issuance(self):
        result = self.navigation(input_text='3\n2\n\n0\n6\n')
        self.assertIn('IPv4: 未配置', result.stdout)
        self.assertIn('IPv6: 未配置', result.stdout)
        self.assertFalse((self.base / 'acme.log').exists())

    def test_empty_dynamic_check_and_disable_return_to_menu(self):
        for action in ('3', '4'):
            with self.subTest(action=action):
                result = self.navigation(input_text='3\n' + action + '\n\n0\n6\n')
                self.assertIn('尚未开通本机动态 IP 证书', result.stdout)
                self.assertIn('已退出', result.stdout)
        self.assertFalse((self.base / 'acme.log').exists())

    def test_dynamic_setup_cancel_before_any_effects(self):
        for text in ('0\n', 'wrong\n0\n', ''):
            with self.subTest(text=text):
                result = self.shell('DYNAMIC_DIR="$TEST_DIR/dynamic"; '
                                    'setup_dynamic_ip_certificate; echo CANCEL_OK', text)
                self.assertIn('CANCEL_OK', result.stdout)
                self.assertFalse((self.base / 'dynamic').exists())

    def test_existing_dynamic_config_requires_explicit_reconfigure(self):
        directory = self.dynamic_fixture()
        config = directory / 'dynamic-ip-v4.conf'
        old = config.read_bytes()
        result = self.navigation(input_text='3\n1\n1\n\n\n0\n6\n')
        self.assertIn('保留原配置', result.stdout)
        self.assertEqual(old, config.read_bytes())
        self.assertFalse((self.base / 'curl.log').exists())

    def test_setup_success_returns_to_combined_submenu(self):
        # Exercise the real setup and config writer, but never issue/install certs.
        body = '''
install_dependencies() { DEPENDENCIES_READY=1; }
configure_firewall() { :; }
ensure_acme() { :; }
register_account() { :; }
install_dynamic_runner() {
    mkdir -p "$DYNAMIC_DIR"
    printf '#!/bin/bash\n. "$1"\nprintf "45.77.170.45\\n" > "$STATE_FILE"\n' > "$DYNAMIC_RUNNER"
    chmod 700 "$DYNAMIC_RUNNER"
}
install_dynamic_cron() { echo "DYNAMIC_CRON=$2"; }
'''
        result = self.navigation(body, '3\n1\n1\ntest@example.com\n1\n\n3\n\n0\n6\n')
        self.assertIn('DYNAMIC_CRON=4', result.stdout)
        self.assertIn('IPv4：已配置；IPv6：未配置', result.stdout)
        self.assertIn('已退出', result.stdout)
        self.assertTrue((self.base / 'dynamic/dynamic-ip-v4.conf').exists())
        self.assertFalse((self.base / 'acme.log').exists())

    def test_failed_action_does_not_disable_errexit_or_kill_menu(self):
        body = '''
setup_dynamic_ip_certificate() {
    echo ACTION_STARTED
    false
    echo INVALID_SUCCESS
}
'''
        result = self.navigation(body, '3\n1\n\n0\n6\n')
        self.assertIn('ACTION_STARTED', result.stdout)
        self.assertNotIn('INVALID_SUCCESS', result.stdout)
        self.assertIn('退出码 1', result.stdout)
        self.assertIn('已退出', result.stdout)

    def test_explicit_exit_is_isolated_from_navigation(self):
        result = self.navigation('setup_dynamic_ip_certificate() { exit 23; }',
                                 '3\n1\n\n0\n6\n')
        self.assertIn('退出码 23', result.stdout)
        self.assertIn('已退出', result.stdout)

    def test_dynamic_family_selection_cancel_default_and_unconfigured(self):
        self.dynamic_fixture((6,))
        body = 'DYNAMIC_DIR="$TEST_DIR/dynamic"; choose_configured_dynamic_family; '
        result = self.shell(body + 'echo "FAMILY=$SELECTED_DYNAMIC_FAMILY"', '\n')
        self.assertIn('FAMILY=6', result.stdout)
        result = self.shell(body + 'echo "FAMILY=$SELECTED_DYNAMIC_FAMILY"', '1\n2\n')
        self.assertIn('该地址类型尚未配置', result.stdout)
        self.assertIn('FAMILY=6', result.stdout)
        self.shell('DYNAMIC_DIR="$TEST_DIR/dynamic"; SELECTED_DYNAMIC_FAMILY=4; '
                   'if choose_configured_dynamic_family; then exit 90; fi; '
                   'test -z "$SELECTED_DYNAMIC_FAMILY"', '0\n')

    def test_dynamic_check_reuses_existing_runner_and_config(self):
        directory = self.dynamic_fixture((4, 6))
        before = {p.name: p.read_bytes() for p in directory.iterdir()}
        result = self.navigation(input_text='3\n3\n2\n\n0\n6\n')
        self.assertIn('CHECKED=' + str(directory / 'dynamic-ip-v6.conf'), result.stdout)
        self.assertEqual(before, {p.name: p.read_bytes() for p in directory.iterdir()})
        self.assertFalse((self.base / 'acme.log').exists())

    def test_failed_dynamic_check_allows_more_actions(self):
        directory = self.dynamic_fixture()
        (directory / 'dynamic_ip_cert.sh').write_text('#!/bin/bash\nexit 17\n')
        result = self.navigation(input_text='3\n3\n1\n\n0\n6\n')
        self.assertIn('退出码 17', result.stdout)
        self.assertIn('已退出', result.stdout)

    def test_dynamic_disable_cancel_preserves_everything(self):
        directory = self.dynamic_fixture()
        before = {p.name: p.read_bytes() for p in directory.iterdir()}
        result = self.navigation(input_text='3\n4\n1\nno\n\n0\n6\n')
        self.assertIn('已取消，原配置和任务保持不变', result.stdout)
        self.assertEqual(before, {p.name: p.read_bytes() for p in directory.iterdir()})

    def test_dynamic_disable_keeps_certs_remote_config_and_other_cron(self):
        directory = self.dynamic_fixture((4, 6))
        (self.base / 'kept.crt').write_text('certificate')
        (self.base / 'kept.key').write_text('private-key')
        remote = self.base / 'remote'
        remote.mkdir()
        (remote / 'device.conf').write_text('remote-device')
        cron = self.base / 'crontab'
        v4 = '*/5 * * * * %s %s\n' % (directory / 'dynamic_ip_cert.sh', directory / 'dynamic-ip-v4.conf')
        v6 = '*/5 * * * * %s %s\n' % (directory / 'dynamic_ip_cert.sh', directory / 'dynamic-ip-v6.conf')
        other = '0 0 * * * /root/.acme.sh/acme.sh --cron\n17 */6 * * * /remote cron home\n'
        cron.write_text(v4 + v6 + other)
        self.write_command('crontab', '''#!/bin/bash
case "$1" in
    -l) cat "$TEST_DIR/crontab" ;;
    -) cat > "$TEST_DIR/crontab.new"; mv "$TEST_DIR/crontab.new" "$TEST_DIR/crontab" ;;
    *) exit 99 ;;
esac
''')
        result = self.navigation(input_text='3\n4\n1\nSTOP\n\n0\n6\n')
        self.assertIn('只移除 IP 变化检测', result.stdout)
        self.assertEqual(v6 + other, cron.read_text())
        self.assertFalse((directory / 'dynamic-ip-v4.conf').exists())
        self.assertTrue((directory / 'dynamic-ip-v6.conf').exists())
        self.assertTrue((directory / 'dynamic_ip_cert.sh').exists())
        self.assertEqual('certificate', (self.base / 'kept.crt').read_text())
        self.assertEqual('private-key', (self.base / 'kept.key').read_text())
        self.assertEqual('remote-device', (remote / 'device.conf').read_text())

    def test_new_remote_entry_is_independent_of_local_dynamic_setup(self):
        body = '''
setup_dynamic_ip_certificate() { echo WRONG_LOCAL_SETUP; exit 90; }
manage_dynamic_ip() { echo WRONG_LOCAL_MENU; exit 91; }
manage_remote_ip_ssl() { CERT_KIND=ip; echo REMOTE_ONLY; }
'''
        result = self.navigation(body, '4\n6\n')
        self.assertIn('REMOTE_ONLY', result.stdout)
        self.assertNotIn('WRONG_LOCAL', result.stdout)
        self.assertFalse((self.base / 'dynamic').exists())
        self.assertFalse((self.base / 'curl.log').exists())
        self.assertEqual(2, result.stdout.count('SSL证书管理菜单'))

    def test_remote_action_error_returns_to_main(self):
        result = self.navigation('manage_remote_ip_ssl() { exit 27; }', '4\n\n6\n')
        self.assertIn('退出码 27', result.stdout)
        self.assertIn('已退出', result.stdout)

    def test_remote_submenu_return_keys_and_eof(self):
        # Extract only the real UI function; do not source remote's top-level
        # directory/SSH initialization or execute any network/ACME operations.
        source = (ROOT / 'remote_ip_ssl.sh').read_text()
        menu = source.split('remote_menu() {', 1)[1].split('\ncron_main()', 1)[0]
        body = ('ensure_runner_installed() { :; }; ensure_local_ssh_key() { :; };\n'
                + 'remote_menu() {' + menu + '\nremote_menu; echo RETURNED')
        for text in ('0\n', '7\n', ''):
            with self.subTest(text=text):
                result = self.shell(body, text)
                self.assertIn('远程设备 IP 证书', result.stdout)
                self.assertIn('配置远端动态公网 IP', result.stdout)
                self.assertIn('RETURNED', result.stdout)

    def test_update_default_cancel_and_error(self):
        result = self.navigation('update_script() { echo UPDATE_STARTED; exit 21; }',
                                 '5\n\n5\ny\n\n6\n')
        self.assertEqual(1, result.stdout.count('UPDATE_STARTED'))
        self.assertIn('已取消更新', result.stdout)
        self.assertIn('退出码 21', result.stdout)
        self.assertIn('已退出', result.stdout)
        self.assertFalse((self.base / 'curl.log').exists())

    def test_successful_update_returns_without_reentering_old_menu(self):
        result = self.navigation('update_script() { echo UPDATED; }', '5\ny\n')
        self.assertIn('UPDATED', result.stdout)
        self.assertEqual(1, result.stdout.count('SSL证书管理菜单'))

    def test_manual_ip_hint_uses_new_remote_entry(self):
        result = self.shell('select_public_ip', '3\n' + V4 + '\n')
        self.assertIn('主菜单 4 的远程设备模式', result.stdout)
        self.assertNotIn('主菜单 5 的远程模式', result.stdout)

    def test_readme_matches_menu_and_stays_concise(self):
        text = (ROOT / 'README.md').read_text()
        self.assertIn('| 3）本机动态 IP 证书 |', text)
        self.assertIn('| 4）远程设备 IP 证书 |', text)
        self.assertIn('进入 **4 → 添加远程设备', text)
        self.assertNotIn('| 4）本机动态 IP 管理 |', text)
        self.assertLessEqual(len(text.splitlines()), 80)

    def test_install_failure_is_not_reported_as_success(self):
        result = self.shell('ACME_BIN="$TEST_DIR/bin/fake-acme"; IDENTIFIER=45.77.170.45; '
                            'issue_static_certificate; echo FALSE_SUCCESS',
                            env={'MOCK_INSTALL_RC': '1'}, expected=None)
        self.assertNotEqual(0, result.returncode)
        self.assertNotIn('FALSE_SUCCESS', result.stdout)


if __name__ == '__main__':
    unittest.main(verbosity=2)
