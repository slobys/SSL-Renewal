#!/usr/bin/env python3
"""OpenWrt ash/cron/firewall lifecycle tests. No real router, network or CA calls.
Certificates are signed by a disposable test CA and checked by real OpenSSL.
"""
import fcntl
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'openwrt_ip_ssl.sh'
V4 = '45.77.170.45'
V6 = '2606:4700:4700::1111'

MOCK = r'''#!/usr/bin/env python3
import json, os, pathlib, subprocess, sys
p = pathlib.Path(os.environ['FIXTURE'])
name = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
with (p/'commands.jsonl').open('a') as f:
    f.write(json.dumps([name, args])+'\n')
def read(name, default):
    path=p/name
    return json.loads(path.read_text()) if path.exists() else default
def save(name, data):
    (p/name).write_text(json.dumps(data))
def value(flag): return args[args.index(flag)+1]
if name=='logger': sys.exit(0)
if name=='ubus':
    print((p/'network.json').read_text()); sys.exit(0)
if name=='jsonfilter':
    data=json.load(sys.stdin); expr=value('-e')
    if expr=='@.l3_device': print(data.get('l3_device',''))
    elif expr=='@.up': print('true' if data.get('up') else 'false')
    elif 'ipv4-address' in expr:
        a=data.get('ipv4-address',[])
        if a: print(a[0]['address'])
    elif 'ipv6-address' in expr:
        for a in data.get('ipv6-address',[]): print(a['address'])
    else: sys.exit(9)
    sys.exit(0)
if name=='netstat':
    print(os.environ.get('MOCK_SOCKETS','')); sys.exit(0)
if name=='ss':
    print(os.environ.get('MOCK_SOCKETS','')); sys.exit(0)
if name=='nft':
    if os.environ.get('MOCK_FW3')=='1': sys.exit(1)
    rules=read('nft.json', {'dstnat':[], 'input':[], 'next':1})
    if 'insert' in args:
        chain=args[4]
        if os.environ.get('MOCK_NFT_FAIL')==chain: sys.exit(2)
        tag=value('comment').strip('"')
        rules[chain].append([rules['next'],tag]); rules['next']+=1
        save('nft.json',rules)
    elif 'list' in args:
        chain=args[-1]
        for handle,tag in rules.get(chain,[]): print('tcp dport 80 comment "%s" # handle %s'%(tag,handle))
    elif 'delete' in args:
        chain=args[4]; handle=int(value('handle'))
        rules[chain]=[r for r in rules[chain] if r[0]!=handle];save('nft.json',rules)
    sys.exit(0)
if name in ('iptables','ip6tables'): sys.exit(0)
if name=='uci':
    args=[a for a in args if a!='-q']; db=read('uci.json',{})
    if args[0]=='get':
        if args[1] not in db: sys.exit(1)
        print(db[args[1]])
    elif args[0]=='set':
        k,v=args[1].split('=',1);db[k]=v;save('uci.json',db)
    elif args[0]=='delete':
        db.pop(args[1],None);save('uci.json',db)
    elif args[0]=='show':
        for k,v in db.items():
            if k.startswith('uhttpd.'): print(k+"='"+v+"'")
    elif args[0]=='changes': print(os.environ.get('MOCK_UCI_CHANGES',''),end='')
    elif args[0]=='export': print(json.dumps(db))
    elif args[0]!='commit': sys.exit(20)
    sys.exit(0)
if name=='uhttpd':
    if os.environ.get('MOCK_RELOAD_FAIL')=='1': sys.exit(23)
    sys.exit(0)
if name=='cron': sys.exit(0)
if name in ('opkg','apk'):
    sys.exit(1 if os.environ.get('MOCK_PACKAGE_FAIL')=='1' else 0)
if name=='curl':
    if '--noproxy' not in args: sys.exit(42)
    print(os.environ.get('MOCK_EXTERNAL', '45.77.170.45'))
    sys.exit(0)
if name=='fake-acme-tool':
    if '--register-account' in args or '--remove' in args: sys.exit(0)
    ip=value('-d'); cache=p/'cache'/ip.replace(':','_'); cache.mkdir(parents=True, exist_ok=True)
    if '--issue' in args:
        if os.environ.get('MOCK_SLOW_ACME')=='1':
            import time
            child=subprocess.Popen(['sleep','30'])
            (p/'acme-child.pid').write_text(str(child.pid))
            time.sleep(30)
        if os.environ.get('MOCK_ASSERT_FD_CLOSED')=='1':
            try: os.fstat(9)
            except OSError: pass
            else: sys.exit(93)
        if os.environ.get('MOCK_ISSUE_FAIL')=='1': sys.exit(11)
        if os.environ.get('MOCK_SKIP')=='1' and (cache/'cert.pem').exists(): sys.exit(2)
        ext=cache/'ext.cnf'
        ext.write_text('basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:'+ip+'\n')
        def run(a): subprocess.run(a, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        run(['openssl','req','-new','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes',
             '-keyout',str(cache/'key.pem'),'-out',str(cache/'csr.pem'),'-subj','/CN=offline-test'])
        run(['openssl','x509','-req','-in',str(cache/'csr.pem'),'-CA',os.environ['TEST_CA'],
             '-CAkey',os.environ['TEST_CA_KEY'],'-set_serial','12345','-days',os.environ.get('MOCK_CERT_DAYS','7'),
             '-extfile',str(ext),'-out',str(cache/'cert.pem')])
        if os.environ.get('MOCK_IP_AFTER_ISSUE'):
            n=read('network.json',{});n['ipv4-address'][0]['address']=os.environ['MOCK_IP_AFTER_ISSUE'];save('network.json',n)
        sys.exit(0)
    if '--install-cert' in args:
        if os.environ.get('MOCK_INSTALL_FAIL')=='1': sys.exit(12)
        import shutil
        shutil.copyfile(cache/'key.pem',value('--key-file'))
        shutil.copyfile(cache/'cert.pem',value('--fullchain-file'))
        sys.exit(0)
    sys.exit(99)
sys.exit(91)
'''


class OpenWrtLocalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ca_tmp = tempfile.TemporaryDirectory(prefix='ssl-test-ca-')
        cls.ca = Path(cls.ca_tmp.name)
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt',
                        'ec_paramgen_curve:P-256', '-nodes', '-days', '30',
                        '-subj', '/CN=SSL-Renewal offline test CA',
                        '-addext', 'basicConstraints=critical,CA:TRUE',
                        '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
                        '-keyout', str(cls.ca/'ca.key'), '-out', str(cls.ca/'ca.crt')],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    @classmethod
    def tearDownClass(cls):
        cls.ca_tmp.cleanup()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='openwrt-ssl-test-')
        self.addCleanup(self.tmp.cleanup)
        self.p = Path(self.tmp.name)
        self.base = self.p/'state'
        self.run = self.p/'run'
        self.bin = self.p/'bin'
        self.init = self.p/'init'
        for directory in (self.base, self.run, self.bin, self.init): directory.mkdir()
        for name in ('ubus', 'jsonfilter', 'logger', 'nft', 'iptables', 'ip6tables',
                     'uci', 'netstat', 'ss', 'curl', 'fake-acme-tool', 'opkg', 'socat'):
            self.command(self.bin/name, MOCK)
        for name in ('uhttpd','cron'): self.command(self.init/name, MOCK)
        self.acme = self.p/'acme.sh'
        self.command(self.acme, '#!/bin/sh\n# --cert-profile\nexec "$FIXTURE/bin/fake-acme-tool" "$@"\n')
        self.wrapper = self.p/'runner.sh'
        self.command(self.wrapper, '#!/bin/sh\nset -eu\nSSL_RENEWAL_OPENWRT_LIBRARY=1\n. '+shlex.quote(str(SCRIPT))+
                     '\now_require() { :; }\now_main "$@"\n')
        self.env = dict(os.environ, PATH=str(self.bin)+os.pathsep+os.environ['PATH'],
                        FIXTURE=str(self.p), TEST_CA=str(self.ca/'ca.crt'), TEST_CA_KEY=str(self.ca/'ca.key'),
                        SSL_CERT_FILE=str(self.ca/'ca.crt'),
                        SSL_RENEWAL_OPENWRT_BASE=str(self.base), SSL_RENEWAL_OPENWRT_RUN=str(self.run),
                        SSL_RENEWAL_OPENWRT_ACME=str(self.acme), SSL_RENEWAL_OPENWRT_SELF=str(self.wrapper),
                        SSL_RENEWAL_OPENWRT_INIT=str(self.init),
                        SSL_RENEWAL_OPENWRT_BACKUPS=str(self.p/'backups'),
                        SSL_RENEWAL_OPENWRT_CRONTAB=str(self.p/'crontab'),
                        PYTHONDONTWRITEBYTECODE='1')
        self.network()
        self.original_uci = {'uhttpd.main':'uhttpd','uhttpd.main.cert':'/original/cert',
                             'uhttpd.main.key':'/original/key','uhttpd.main.listen_http':'192.168.2.1:80'}
        (self.p/'uci.json').write_text(json.dumps(self.original_uci))
        self.config()

    @staticmethod
    def command(path, text):
        path.write_text(text)
        path.chmod(0o700)

    def network(self, ip=V4, v6=V6, up=True, device='pppoe-wan'):
        (self.p/'network.json').write_text(json.dumps({'up':up,'l3_device':device,
                            'ipv4-address':[{'address':ip}], 'ipv6-address':[{'address':v6}]}))

    def config(self, family=4, **kwargs):
        values = dict(MODE='dynamic', SOURCE='wan', NETWORK='wan' if family==4 else 'wan6',
                      FIXED_IP='', EMAIL='test@example.com', CHALLENGE='http', DEPLOY='files',
                      UHTTPD_SECTION='main', RELOAD_CMD='')
        values.update(kwargs)
        (self.base/('v%d.conf'%family)).write_text(''.join(k+'='+v+'\n' for k,v in values.items()))

    def calls(self, name=None, flag=None):
        f=self.p/'commands.jsonl'
        rows=[json.loads(line) for line in f.read_text().splitlines()] if f.exists() else []
        return [args for cmd,args in rows if (name is None or cmd==name) and (flag is None or flag in args)]

    def cli(self, *args, env=None, expected=0, input_text=''):
        result=subprocess.run(['sh',str(self.wrapper),*args], env=dict(self.env,**(env or {})),
                              text=True,input=input_text,capture_output=True,timeout=30)
        if expected is not None: self.assertEqual(expected,result.returncode,result.stdout+result.stderr)
        return result

    def shell(self, body, env=None, expected=0, interpreter=None, input_text=''):
        command=(interpreter or ['sh'])+['-c','set -eu; SSL_RENEWAL_OPENWRT_LIBRARY=1; . "$1"; '+body,
                                       'ow-test',str(SCRIPT)]
        result=subprocess.run(command,env=dict(self.env,**(env or {})),capture_output=True,
                              text=True,input=input_text,timeout=30)
        if expected is not None: self.assertEqual(expected,result.returncode,result.stdout+result.stderr)
        return result

    def assert_firewall_clean(self):
        f=self.p/'nft.json'
        if f.exists():
            rules=json.loads(f.read_text())
            self.assertEqual([],rules['dstnat'])
            self.assertEqual([],rules['input'])

    def test_ash_and_dash_syntax(self):
        for file in ('acme.sh','openwrt_ip_ssl.sh'):
            subprocess.run(['sh','-n',str(ROOT/file)],check=True)
            if shutil.which('busybox'): subprocess.run(['busybox','ash','-n',str(ROOT/file)],check=True)

    def test_sourcing_has_no_side_effects(self):
        self.assertEqual('OK\n',self.shell('echo OK').stdout)
        self.assertFalse((self.p/'commands.jsonl').exists())

    def test_native_mode_rejects_non_openwrt(self):
        if Path('/etc/openwrt_release').exists(): self.skipTest('real OpenWrt host')
        r=subprocess.run(['sh',str(SCRIPT),'menu'],env=self.env,capture_output=True,text=True)
        self.assertNotEqual(0,r.returncode)
        self.assertFalse(self.calls('fake-acme-tool'))

    def test_public_ip_normalization_under_ash(self):
        interpreter=['busybox','ash'] if shutil.which('busybox') else ['sh']
        for value,family,expected in [(V4,4,V4),(' [2606:4700:4700:0:0:0:0:1111] ',6,V6),
                        ('240e:1234::1',6,'240e:1234::1'),('240e:0:0:1234:0:0:0:1',6,'240e:0:0:1234::1')]:
            with self.subTest(value=value):
                r=self.shell('ow_ip "$CANDIDATE" "$FAMILY_TEST"',{'CANDIDATE':value,'FAMILY_TEST':str(family)},interpreter=interpreter)
                self.assertEqual(expected+'\n',r.stdout)

    def test_invalid_and_reserved_addresses(self):
        for family, values in [(4,['10.0.0.1','127.0.0.1','100.64.0.1','192.168.2.1','224.0.0.1',
              '192.0.2.1','203.0.113.2','198.51.100.5','0.0.0.0','1.2.3.256','01.2.3.4',V4+':443',V4+'/24',
              'https://'+V4,'1.2.3.4\n1.1.1.1']),
              (6,['::1','::','fe80::1','fc00::1','ff02::1','2001:db8::1','::ffff:45.77.170.45',
                  '2606:::1111','2606::1::1','2606:4700::1%eth0','2606:4700:0:0:0:0:0:0:1','3fff::1'])]:
            for value in values:
                with self.subTest(value=value):
                    r=self.shell('ow_ip "$CANDIDATE" "$FAMILY_TEST"',{'CANDIDATE':value,'FAMILY_TEST':str(family)},expected=None)
                    self.assertNotEqual(0,r.returncode)

    def test_config_is_data_not_executable_shell(self):
        file=self.base/'v4.conf'
        file.write_text(file.read_text()+'UNKNOWN=$(touch '+str(self.p/'pwned')+')\n')
        self.assertNotEqual(0,self.cli('check','4',expected=None).returncode)
        self.assertFalse((self.p/'pwned').exists())
        self.assertFalse(self.calls('fake-acme-tool'))

    def test_first_issue_then_unchanged_no_duplicate(self):
        self.cli('check','4')
        live=self.base/'certs/v4/current'
        self.assertTrue(live.is_symlink())
        self.assertEqual(V4,(self.base/'v4.ip').read_text().strip())
        self.cli('check','4')
        self.assertEqual(1,len(self.calls('fake-acme-tool','--issue')))
        self.assert_firewall_clean()

    def test_dynamic_ip_change_resigns(self):
        self.cli('check','4')
        self.network(ip='1.1.1.1')
        self.cli('check','4')
        self.assertEqual('1.1.1.1',(self.base/'v4.ip').read_text().strip())
        self.assertEqual(2,len(self.calls('fake-acme-tool','--issue')))
        self.assertTrue(self.calls('fake-acme-tool','--remove'))
        self.assert_firewall_clean()

    def test_same_ip_near_expiry_renews(self):
        self.cli('check','4',env={'MOCK_CERT_DAYS':'2'})
        self.cli('check','4')
        self.assertEqual(2,len(self.calls('fake-acme-tool','--issue')))
        self.assert_firewall_clean()

    def test_changed_ip_issue_failure_preserves_live_pair_and_retries_backoff(self):
        self.cli('check','4')
        previous=os.readlink(self.base/'certs/v4/current')
        self.network(ip='1.1.1.1')
        r=self.cli('check','4',env={'MOCK_ISSUE_FAIL':'1'},expected=None)
        self.assertNotEqual(0,r.returncode)
        self.assertEqual(previous,os.readlink(self.base/'certs/v4/current'))
        self.assertEqual(V4,(self.base/'v4.ip').read_text().strip())
        attempts=len(self.calls('fake-acme-tool','--issue'))
        self.cli('check','4')
        self.assertEqual(attempts,len(self.calls('fake-acme-tool','--issue')))
        self.assertTrue((self.run/'v4.retry').exists())
        self.assert_firewall_clean()

    def test_new_ip_bypasses_old_ip_backoff(self):
        self.cli('check','4',env={'MOCK_ISSUE_FAIL':'1'},expected=None)
        self.network(ip='1.1.1.1')
        self.cli('check','4')
        self.assertEqual('1.1.1.1',(self.base/'v4.ip').read_text().strip())

    def test_failed_install_not_committed(self):
        r=self.cli('check','4',env={'MOCK_INSTALL_FAIL':'1'},expected=None)
        self.assertNotEqual(0,r.returncode)
        self.assertFalse((self.base/'certs/v4/current').exists())
        self.assertFalse((self.base/'v4.ip').exists())
        self.assert_firewall_clean()

    def test_uhttpd_deployment_changes_only_cert_paths(self):
        self.config(DEPLOY='uhttpd')
        self.cli('check','4')
        db=json.loads((self.p/'uci.json').read_text())
        self.assertEqual(self.original_uci['uhttpd.main.listen_http'],db['uhttpd.main.listen_http'])
        self.assertIn('/current/fullchain.pem',db['uhttpd.main.cert'])
        self.assertTrue((self.base/'backups/uhttpd.original').exists())
        self.assertEqual([['restart']],self.calls('uhttpd'))
        self.assertEqual(0o600,(self.base/'certs/v4/current/privkey.pem').stat().st_mode & 0o777)

    def test_reload_failure_rolls_back_and_pending_certificate_reused(self):
        self.config(DEPLOY='uhttpd');self.cli('check','4')
        old=os.readlink(self.base/'certs/v4/current'); old_uci=(self.p/'uci.json').read_text()
        self.network(ip='1.1.1.1')
        self.assertNotEqual(0,self.cli('check','4',env={'MOCK_RELOAD_FAIL':'1'},expected=None).returncode)
        self.assertEqual(old,os.readlink(self.base/'certs/v4/current'))
        self.assertEqual(old_uci,(self.p/'uci.json').read_text())
        self.assertEqual(V4,(self.base/'v4.ip').read_text().strip())
        count=len(self.calls('fake-acme-tool','--issue'))
        (self.run/'v4.retry').unlink()
        self.cli('check','4')
        self.assertEqual(count,len(self.calls('fake-acme-tool','--issue')))
        self.assertEqual('1.1.1.1',(self.base/'v4.ip').read_text().strip())
        self.assert_firewall_clean()

    def test_config_change_applies_without_resigning(self):
        self.cli('check','4');self.config(DEPLOY='uhttpd');self.cli('check','4')
        self.assertEqual(1,len(self.calls('fake-acme-tool','--issue')))
        self.assertEqual([['restart']],self.calls('uhttpd'))

    def test_real_openssl_rejects_wrong_ip_key_and_untrusted_chain(self):
        self.cli('check','4')
        cert=self.base/'certs/v4/current/fullchain.pem'; key=self.base/'certs/v4/current/privkey.pem'
        body='ow_certificate_valid "$CERT" "$KEY" "$TARGET_TEST" 3600'
        env={'CERT':str(cert),'KEY':str(key),'TARGET_TEST':V4}
        self.shell(body,env)
        self.assertNotEqual(0,self.shell(body,dict(env,TARGET_TEST='1.1.1.1'),expected=None).returncode)
        self.assertNotEqual(0,self.shell(body,dict(env,KEY=str(self.ca/'ca.key')),expected=None).returncode)
        self.assertNotEqual(0,self.shell(body,dict(env,SSL_CERT_FILE='/nonexistent',SSL_CERT_DIR=str(self.p)),expected=None).returncode)

    def test_finite_firewall_rules_are_wan_and_destination_scoped(self):
        self.cli('check','4')
        inserts=[a for a in self.calls('nft') if a and a[0]=='insert']
        self.assertEqual(2,len(inserts))
        for a in inserts: self.assertEqual('pppoe-wan',a[a.index('iifname')+1])
        nat=inserts[0]; self.assertEqual(V4,nat[nat.index('daddr')+1]);self.assertIn('ipv4',nat)
        self.assertIn('dnat',inserts[1]);self.assertNotIn('flush',str(self.calls('nft')))
        self.assert_firewall_clean()

    def test_partial_firewall_failure_cleans_first_rule_and_does_not_issue(self):
        self.assertNotEqual(0,self.cli('check','4',env={'MOCK_NFT_FAIL':'input'},expected=None).returncode)
        self.assertFalse(self.calls('fake-acme-tool','--issue'))
        self.assert_firewall_clean()

    def test_http_uses_high_local_port_without_stopping_luci(self):
        self.cli('check','4')
        issue=self.calls('fake-acme-tool','--issue')[0]
        self.assertIn('--standalone',issue);self.assertIn('--httpport',issue)
        self.assertEqual('38084',issue[issue.index('--httpport')+1])
        self.assertFalse(self.calls('uhttpd'))

    def test_alpn_uses_public443_and_high_tls_port(self):
        self.config(CHALLENGE='alpn');self.cli('check','4')
        issue=self.calls('fake-acme-tool','--issue')[0]
        self.assertIn('--alpn',issue);self.assertIn('--tlsport',issue)
        nat=[a for a in self.calls('nft') if a and a[0]=='insert'][0]
        self.assertEqual('443',nat[nat.index('dport')+1]);self.assert_firewall_clean()

    def test_ipv6_local_issue_and_rule_scope(self):
        self.config(6);self.cli('check','6')
        self.assertEqual(V6,(self.base/'v6.ip').read_text().strip())
        issue=self.calls('fake-acme-tool','--issue')[0];self.assertIn('--listen-v6',issue)
        nat=[a for a in self.calls('nft') if a and a[0]=='insert'][0]
        self.assertIn('ipv6',nat);self.assertIn('ip6',nat);self.assert_firewall_clean()

    def test_ipv6_skips_linklocal_address_and_keeps_stable_existing(self):
        self.config(6)
        data=json.loads((self.p/'network.json').read_text())
        data['ipv6-address']=[{'address':'fe80::1'},{'address':V6}]
        (self.p/'network.json').write_text(json.dumps(data));self.cli('check','6')
        data['ipv6-address'].insert(0,{'address':'2606:4700::1234'})
        (self.p/'network.json').write_text(json.dumps(data));self.cli('check','6')
        self.assertEqual(1,len(self.calls('fake-acme-tool','--issue')))
        self.assertEqual(V6,(self.base/'v6.ip').read_text().strip())

    def test_fixed_ip_behind_nat(self):
        self.config(MODE='fixed',FIXED_IP=V4);self.network(ip='192.168.1.2')
        self.cli('check','4')
        nat=[a for a in self.calls('nft') if a and a[0]=='insert'][0]
        self.assertIn('192.168.1.2',nat)
        self.assertEqual(V4,(self.base/'v4.ip').read_text().strip())

    def test_external_ip_discovery_is_bound_to_wan_and_no_proxy(self):
        self.config(SOURCE='external');self.network(ip='192.168.1.2');self.cli('check','4')
        for call in self.calls('curl'):
            self.assertIn('--noproxy',call);self.assertIn('--proxy',call)
            self.assertEqual('pppoe-wan',call[call.index('--interface')+1])

    def test_lan_interface_is_rejected(self):
        self.config(NETWORK='lan')
        self.assertNotEqual(0,self.cli('check','4',expected=None).returncode)
        self.assertFalse(self.calls('fake-acme-tool'))

    def test_network_down_and_private_ip_do_not_request_ca(self):
        for kwargs in ({'up':False},{'ip':'192.168.1.2'},{'device':'br-lan'}):
            self.network(**kwargs)
            self.assertNotEqual(0,self.cli('check','4',expected=None).returncode)
        self.assertFalse(self.calls('fake-acme-tool'))

    def test_ip_changes_during_issuance_no_wrong_deployment(self):
        r=self.cli('check','4',env={'MOCK_IP_AFTER_ISSUE':'1.1.1.1'},expected=None)
        self.assertNotEqual(0,r.returncode)
        self.assertFalse((self.base/'certs/v4/current').exists())
        self.assertFalse((self.base/'v4.ip').exists());self.assert_firewall_clean()

    def test_legacy_fw3_ipv4_and_ipv6(self):
        self.cli('check','4',env={'MOCK_FW3':'1'})
        self.assertTrue(self.calls('iptables'))
        self.config(6);self.cli('check','6',env={'MOCK_FW3':'1'})
        self.assertTrue(self.calls('ip6tables'))

    def test_own_lock_prevents_overlapping_ca_jobs(self):
        with (self.run/'operation.lock').open('w') as f:
            fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)
            result=self.cli('check','4')
            self.assertIn('已有证书操作',result.stdout)
            self.assertFalse(self.calls('fake-acme-tool'))

    def test_disabled_manager_does_not_renew(self):
        (self.base/'v4.disabled').touch();self.cli('check','4')
        self.assertFalse(self.calls('fake-acme-tool'))

    def test_cron_idempotent_and_preserves_other_jobs(self):
        other='0 0 * * * /other/job\n'
        (self.p/'crontab').write_text(other)
        self.shell('ow_cron; ow_cron')
        text=(self.p/'crontab').read_text()
        self.assertTrue(text.startswith(other));self.assertEqual(1,text.count('# ssl-renewal-openwrt-local'))
        (self.base/'v4.disabled').touch();self.shell('ow_cron')
        self.assertEqual(other,(self.p/'crontab').read_text())

    def test_toggle_requires_stop_preserves_cert_and_can_resume(self):
        self.cli('check','4');self.shell('ow_cron')
        live=(self.base/'certs/v4/current/fullchain.pem').read_bytes()
        self.cli('toggle',input_text='1\nno\n')
        self.assertFalse((self.base/'v4.disabled').exists())
        self.cli('toggle',input_text='1\nSTOP\n')
        self.assertTrue((self.base/'v4.disabled').exists())
        self.assertEqual(live,(self.base/'certs/v4/current/fullchain.pem').read_bytes())
        self.cli('toggle',input_text='1\n')
        self.assertFalse((self.base/'v4.disabled').exists())

    def test_setup_cancel_does_not_install_or_request_ca(self):
        (self.base/'v4.conf').unlink()
        self.cli('setup',input_text='0\n')
        self.assertFalse(self.calls('opkg'));self.assertFalse(self.calls('fake-acme-tool'))

    def test_openwrt_setup_complete_dynamic_flow(self):
        (self.base/'v4.conf').unlink()
        self.cli('setup',input_text='1\n1\n\n1\ntest@example.com\n1\n1\n\nYES\n')
        self.assertTrue(self.calls('opkg'))
        self.assertEqual(V4,(self.base/'v4.ip').read_text().strip())
        self.assertIn('check-all',(self.p/'crontab').read_text())
        self.assert_firewall_clean()

    def test_setup_confirmation_accepts_yes_case_variants(self):
        (self.base/'v4.conf').unlink()
        prefix='1\n1\nwan\n\ntest@example.com\n\n2\n\n'
        # Exercise the actual setup prompt up to the dependency boundary without
        # installing packages, modifying UCI or requesting any certificate.
        body='ow_require() { :; }; ow_dependencies() { echo CONFIRM_ACCEPTED; exit 0; }; ow_setup'
        interpreters=[['sh']]
        if shutil.which('busybox'): interpreters.append(['busybox','ash'])
        for interpreter in interpreters:
            for answer in ('yes','YES','Yes','yEs','yeS','YEs','yES','YeS'):
                with self.subTest(interpreter=interpreter, answer=answer):
                    r=self.shell(body,interpreter=interpreter,input_text=prefix+answer+'\n')
                    self.assertIn('CONFIRM_ACCEPTED',r.stdout)
                    self.assertIn('输入 yes / YES（回车取消）',r.stdout)
                    self.assertNotIn('已取消',r.stdout)
        self.assertFalse(self.calls('opkg'))
        self.assertFalse(self.calls('fake-acme-tool'))
        self.assertFalse((self.base/'v4.conf').exists())

    def test_setup_confirmation_still_cancels_on_blank_no_invalid_or_eof(self):
        (self.base/'v4.conf').unlink()
        prefix='1\n1\nwan\n\ntest@example.com\n\n2\n\n'
        body='ow_require() { :; }; ow_dependencies() { echo MUST_NOT_INSTALL; exit 91; }; ow_setup'
        for answer in ('\n','no\n','NO\n','y\n','Y\n','YESplease\n','yes no\n','1\n',''):
            with self.subTest(answer=answer):
                r=self.shell(body,input_text=prefix+answer)
                self.assertNotIn('MUST_NOT_INSTALL',r.stdout)
        self.assertFalse(self.calls('opkg'))
        self.assertFalse(self.calls('fake-acme-tool'))
        self.assertFalse(self.calls('uci','set'))
        self.assertFalse((self.base/'v4.conf').exists())
        self.assertFalse((self.p/'crontab').exists())

    def test_setup_lowercase_yes_completes_uhttpd_flow(self):
        (self.base/'v4.conf').unlink()
        r=self.cli('setup',input_text='1\n1\nwan\n\ntest@example.com\n\n2\n\nyes\n')
        self.assertNotIn('已取消',r.stdout)
        self.assertTrue(self.calls('opkg'))
        self.assertEqual(V4,(self.base/'v4.ip').read_text().strip())
        live=self.base/'certs/v4/current'
        config=json.loads((self.p/'uci.json').read_text())
        self.assertEqual(str(live/'fullchain.pem'),config['uhttpd.main.cert'])
        self.assertEqual(str(live/'privkey.pem'),config['uhttpd.main.key'])
        self.assertTrue(self.calls('uhttpd','restart'))
        self.assertIn('check-all',(self.p/'crontab').read_text())
        self.assert_firewall_clean()

    def test_setup_apk_branch(self):
        self.command(self.bin/'apk',MOCK)
        (self.base/'v4.conf').unlink()
        self.cli('setup',input_text='1\n1\n\n1\ntest@example.com\n1\n1\n\nYES\n')
        self.assertTrue(self.calls('apk'));self.assertFalse(self.calls('opkg'))

    def test_package_install_failure_does_not_enable_cron(self):
        (self.base/'v4.conf').unlink()
        r=self.cli('setup',input_text='1\n1\n\n1\ntest@example.com\n1\n1\n\nYES\n',env={'MOCK_PACKAGE_FAIL':'1'},expected=None)
        self.assertNotEqual(0,r.returncode)
        self.assertFalse((self.p/'crontab').exists());self.assertFalse(self.calls('fake-acme-tool'))

    def test_setup_uhttpd_dual_family_collision_rejected(self):
        self.config(6,DEPLOY='uhttpd')
        (self.base/'v4.conf').unlink()
        r=self.cli('setup',input_text='1\n1\n\n1\ntest@example.com\n1\n2\n\n',expected=None)
        self.assertNotEqual(0,r.returncode);self.assertIn('互相覆盖',r.stdout)
        self.assertFalse(self.calls('opkg'))

    def test_menu_eof_and_exit_no_ca(self):
        for text in ('','0\n','wrong\n0\n'):
            r=self.cli('menu',input_text=text)
            self.assertIn('OpenWrt 本机 IP 证书',r.stdout)
            self.assertIn('1）申请 / 重新配置（动态或固定公网 IP）',r.stdout)
            self.assertNotIn('1）开通 / 重新配置（动态或固定公网 IP）',r.stdout)
        self.assertFalse(self.calls('fake-acme-tool'))

    def test_status_before_and_after_success(self):
        r=self.cli('status');self.assertIn('尚未成功',r.stdout)
        self.cli('check','4');r=self.cli('status')
        self.assertIn(V4,r.stdout);self.assertIn('notAfter=',r.stdout)

    def test_timeout_releases_lock_and_cleans_firewall_and_child(self):
        result=self.cli('check','4',env={'MOCK_SLOW_ACME':'1',
                       'SSL_RENEWAL_OPENWRT_ACME_TIMEOUT':'1'},expected=None)
        self.assertNotEqual(0,result.returncode)
        self.assert_firewall_clean()
        with (self.run/'operation.lock').open('w') as f:
            fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)
        child=int((self.p/'acme-child.pid').read_text())
        stat=Path('/proc/%d/stat'%child)
        # A reaped process is absent; an unreaped zombie cannot hold a listener.
        if stat.exists(): self.assertEqual('Z',stat.read_text().split(') ',1)[1].split()[0])

    def test_acme_child_does_not_inherit_manager_lock_fd(self):
        self.cli('check','4',env={'MOCK_ASSERT_FD_CLOSED':'1'})
        self.assertEqual(V4,(self.base/'v4.ip').read_text().strip())

    def test_cached_skip_with_short_expiry_does_not_loop_reload(self):
        self.cli('check','4',env={'MOCK_CERT_DAYS':'2'})
        old=os.readlink(self.base/'certs/v4/current')
        result=self.cli('check','4',env={'MOCK_SKIP':'1'},expected=None)
        self.assertNotEqual(0,result.returncode)
        self.assertEqual(old,os.readlink(self.base/'certs/v4/current'))
        self.assertTrue((self.run/'v4.retry').exists())
        self.assert_firewall_clean()

    def uninstall_cron(self):
        own='*/5 * * * * /bin/sh %s check-all >/dev/null 2>&1 # ssl-renewal-openwrt-local\n' % self.wrapper
        other='0 2 * * * /another/job # ssl-renewal-openwrt-local unrelated\n'
        (self.p/'crontab').write_text(own+other)
        return other

    def test_uninstall_cancel_and_eof_have_no_effects(self):
        old=self.wrapper.read_bytes()
        conf=(self.base/'v4.conf').read_bytes()
        for text in ('','0\n','wrong\n','1\n','2\nno\n'):
            self.cli('uninstall',input_text=text)
        self.assertEqual(old,self.wrapper.read_bytes())
        self.assertEqual(conf,(self.base/'v4.conf').read_bytes())
        self.assertFalse((self.p/'backups').exists())
        self.assertFalse(self.calls('uci'))

    def test_uninstall_keep_stops_own_jobs_preserves_cert_and_uci(self):
        self.config(DEPLOY='uhttpd'); self.cli('check','4')
        before=(self.base/'certs/v4/current/fullchain.pem').read_bytes()
        uci=(self.p/'uci.json').read_bytes()
        other=self.uninstall_cron()
        result=self.cli('uninstall',input_text='1\nUNINSTALL\n')
        self.assertIn('卸载完成',result.stdout)
        self.assertFalse(self.wrapper.exists())
        self.assertTrue((self.base/'v4.disabled').exists())
        self.assertEqual(before,(self.base/'certs/v4/current/fullchain.pem').read_bytes())
        self.assertEqual(uci,(self.p/'uci.json').read_bytes())
        self.assertEqual(other,(self.p/'crontab').read_text())
        self.assertTrue((self.run/'uninstalled').exists())
        self.assertFalse(self.calls('opkg'))

    def test_uninstall_purge_archives_data_and_preserves_shared_client(self):
        self.cli('check','4'); other=self.uninstall_cron()
        old=(self.base/'certs/v4/current/fullchain.pem').read_bytes()
        self.cli('uninstall',input_text='2\nPURGE\n')
        self.assertFalse(self.base.exists()); self.assertFalse(self.wrapper.exists())
        self.assertTrue(self.acme.exists())
        backup=next((self.p/'backups').iterdir())
        self.assertEqual(0o700,backup.stat().st_mode & 0o777)
        self.assertEqual(old,(backup/'data/certs/v4/current/fullchain.pem').read_bytes())
        self.assertEqual(other,(self.p/'crontab').read_text())
        self.assertFalse(self.calls('uhttpd'))

    def test_uninstall_purge_migrates_luci_references_only(self):
        self.config(DEPLOY='uhttpd'); self.cli('check','4')
        original=(self.base/'certs/v4/current/fullchain.pem').read_bytes()
        db=json.loads((self.p/'uci.json').read_text())
        db['uhttpd.main.listen_http']='192.168.2.1:8888'
        (self.p/'uci.json').write_text(json.dumps(db))
        self.uninstall_cron()
        self.cli('uninstall',input_text='2\nPURGE\n')
        after=json.loads((self.p/'uci.json').read_text())
        self.assertEqual('192.168.2.1:8888',after['uhttpd.main.listen_http'])
        self.assertEqual(original,Path(after['uhttpd.main.cert']).read_bytes())
        self.assertTrue(Path(after['uhttpd.main.key']).is_file())
        self.assertTrue(after['uhttpd.main.cert'].startswith(str(self.p/'backups')))
        self.assertFalse(self.base.exists())

    def test_uninstall_purge_reload_failure_rolls_back_and_keeps_files(self):
        self.config(DEPLOY='uhttpd'); self.cli('check','4'); self.uninstall_cron()
        before=(self.p/'uci.json').read_bytes(); cron=(self.p/'crontab').read_bytes()
        result=self.cli('uninstall',input_text='2\nPURGE\n',env={'MOCK_RELOAD_FAIL':'1'},expected=None)
        self.assertNotEqual(0,result.returncode)
        self.assertEqual(before,(self.p/'uci.json').read_bytes())
        self.assertEqual(cron,(self.p/'crontab').read_bytes())
        self.assertTrue(self.wrapper.exists()); self.assertTrue(self.base.exists())
        self.assertFalse((self.run/'uninstalled').exists())

    def test_uninstall_pending_uci_edit_blocks_clean_mode(self):
        self.config(DEPLOY='uhttpd'); self.cli('check','4'); self.uninstall_cron()
        result=self.cli('uninstall',input_text='2\nPURGE\n',env={'MOCK_UCI_CHANGES':"uhttpd.main.foo='pending'"},expected=None)
        self.assertNotEqual(0,result.returncode)
        self.assertTrue(self.wrapper.exists()); self.assertTrue(self.base.exists())

    def test_uninstall_busy_operation_does_not_delete(self):
        cron=self.uninstall_cron(); before=(self.p/'crontab').read_bytes()
        with (self.run/'operation.lock').open('w') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            result=self.cli('uninstall',input_text='2\nPURGE\n')
        self.assertIn('已有证书操作',result.stdout)
        self.assertTrue(self.wrapper.exists()); self.assertTrue(self.base.exists())
        self.assertEqual(before,(self.p/'crontab').read_bytes())
        self.assertFalse((self.p/'backups').exists())

    def test_uninstall_does_not_follow_backup_or_data_symlinks(self):
        victim=self.p/'victim'; victim.mkdir(); (victim/'important').write_text('keep')
        (self.p/'backups').symlink_to(victim,target_is_directory=True)
        result=self.cli('uninstall',input_text='2\nPURGE\n',expected=None)
        self.assertNotEqual(0,result.returncode)
        self.assertTrue(self.wrapper.exists()); self.assertEqual('keep',(victim/'important').read_text())

    def test_uninstall_reinstall_keep_config_can_resume(self):
        wrapper=self.wrapper.read_bytes(); self.cli('check','4')
        self.cli('uninstall',input_text='1\nUNINSTALL\n')
        self.wrapper.write_bytes(wrapper); self.wrapper.chmod(0o700)
        self.cli('check','4')
        self.assertEqual(1,len(self.calls('fake-acme-tool','--issue')))
        self.cli('toggle',input_text='1\n')
        self.assertFalse((self.run/'uninstalled').exists())
        self.assertFalse((self.base/'v4.disabled').exists())
        self.assertIn('check-all',(self.p/'crontab').read_text())

    def test_uninstall_refuses_unknown_files_in_clean_scope(self):
        (self.base/'unrelated.conf').write_text('keep')
        result=self.cli('uninstall',input_text='2\nPURGE\n',expected=None)
        self.assertNotEqual(0,result.returncode)
        self.assertTrue(self.wrapper.exists())
        self.assertEqual('keep',(self.base/'unrelated.conf').read_text())

    def test_uninstall_unconfigured_program_does_not_require_flock(self):
        (self.base/'v4.conf').unlink()
        body='''ow_require() { :; }
command() {
    if [ "$1" = -v ] && [ "$2" = flock ]; then return 1; fi
    builtin command "$@"
}
ow_uninstall
'''
        result=self.shell(body,input_text='1\nUNINSTALL\n',interpreter=['bash'])
        self.assertIn('卸载完成',result.stdout)
        self.assertFalse(self.wrapper.exists())

    def test_uninstall_keep_removes_only_dedicated_client(self):
        client=self.base/'client';client.mkdir()
        (client/'acme.sh').write_text('# dedicated ACME')
        self.cli('uninstall',input_text='1\nUNINSTALL\n')
        self.assertFalse((client/'acme.sh').exists())
        self.assertTrue(self.acme.exists())
        backup=next((self.p/'backups').iterdir())
        self.assertTrue((backup/'data/client/acme.sh').exists())

    def test_reinstall_restore_fetches_client_before_enabling_jobs(self):
        (self.base/'v4.disabled').touch(); (self.run/'uninstalled').touch()
        body='''ow_require() { :; }
ow_client() { echo CLIENT_RESTORED; }
ow_toggle
'''
        result=self.shell(body,input_text='1\n')
        self.assertIn('CLIENT_RESTORED',result.stdout)
        self.assertFalse((self.run/'uninstalled').exists())
        self.assertIn('check-all',(self.p/'crontab').read_text())

    def test_uninstall_native_menu_exits_after_removal(self):
        result=self.cli('menu',input_text='5\n1\nUNINSTALL\n')
        self.assertIn('卸载完成',result.stdout)
        self.assertFalse(self.wrapper.exists())

    def test_uninstall_stale_check_observes_stop_marker(self):
        (self.run/'uninstalled').touch()
        self.cli('check','4')
        self.assertFalse(self.calls('fake-acme-tool'))

    def test_uninstall_shell_guard_and_idempotent_no_install(self):
        self.shell('ow_require() { :; }; ow_uninstall',input_text='2\nPURGE\n',
                   interpreter=['busybox','ash'] if shutil.which('busybox') else None)
        self.shell('ow_require() { :; }; ow_uninstall',input_text='2\nPURGE\n')
        self.assertFalse(self.base.exists())
        self.assertFalse(self.calls('opkg'))

    def test_bootstrap_openwrt_before_bash_git_or_linux_packages(self):
        # Emulate filesystem identity ONLY in an isolated copy of the actual entry.
        source=(ROOT/'acme.sh').read_text()
        marker=self.p/'openwrt_release';marker.touch()
        install=self.p/'installed'
        source=source.replace('[ -f /etc/openwrt_release ]','[ -f '+shlex.quote(str(marker))+' ]')
        source=source.replace('TARGET_DIR=/root/.ssl-renewal/openwrt','TARGET_DIR='+shlex.quote(str(install)))
        entry=self.p/'entry.sh';entry.write_text(source)
        self.command(self.bin/'id','#!/bin/sh\necho 0\n')
        self.command(self.bin/'curl',r'''#!/usr/bin/env python3
import pathlib,sys
args=sys.argv[1:]
pathlib.Path(args[args.index('-o')+1]).write_text('#!/bin/sh\necho NATIVE_OPENWRT_MENU\n')
''')
        for cmd in ('bash','git','apt-get','yum','dnf'):
            self.command(self.bin/cmd,'#!/bin/sh\necho UNEXPECTED_LINUX_DEPENDENCY >&2\nexit 99\n')
        r=subprocess.run(['sh',str(entry)],env=self.env,capture_output=True,text=True,timeout=10)
        self.assertEqual(0,r.returncode,r.stdout+r.stderr)
        self.assertIn('NATIVE_OPENWRT_MENU',r.stdout)
        self.assertNotIn('UNEXPECTED_LINUX_DEPENDENCY',r.stdout+r.stderr)


if __name__=='__main__':
    unittest.main(verbosity=2)
