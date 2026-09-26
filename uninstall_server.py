#!/usr/bin/env python3
"""SSL-Renewal server uninstaller. Never uninstall a shared ACME client or packages.

Deletion is limited to known project scripts and selected project config/log files.
All certificates, private keys, ~/.acme.sh, SSH material and other cron jobs remain.
Environment roots are for isolated regression tests, not alternate install discovery.
"""
import fcntl
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile


class UninstallError(RuntimeError):
    pass


def unlink_existing(path):
    try:
        path.unlink()
    except FileNotFoundError:
        pass


class ServerUninstaller:
    def __init__(self, root=None, run=None):
        self.root = Path(root or os.environ.get('SSL_RENEWAL_UNINSTALL_ROOT', '/root'))
        self.run = Path(run or os.environ.get('SSL_RENEWAL_UNINSTALL_RUN', '/run'))
        self.base = self.root / '.ssl-renewal'
        self.busy = self.base / 'server.uninstalling'
        self.disabled = self.base / 'server.uninstalled'
        self.scripts = {
            self.root / 'acme.sh': 'slobys/SSL-Renewal',
            self.root / 'acme_3.0.sh': 'SSL证书管理菜单',
            self.root / 'dynamic_ip_cert.sh': 'dynamic-ip-v',
            self.root / 'remote_ip_ssl.sh': 'remote-ip-ssl',
            self.root / 'openwrt_ip_ssl.sh': 'OpenWrt local IP certificates',
            self.root / 'uninstall_server.py': 'SSL-Renewal server uninstaller',
            self.base / 'dynamic_ip_cert.sh': 'dynamic-ip-v',
            self.base / 'remote' / 'remote_ip_ssl.sh': 'remote-ip-ssl',
        }

    @staticmethod
    def safe_path(path):
        path = Path(path)
        if not path.is_absolute() or '..' in path.parts:
            raise UninstallError('路径必须是绝对路径且不能含 ..：' + str(path))
        for part in (path,) + tuple(path.parents):
            if part.is_symlink():
                raise UninstallError('拒绝操作带符号链接的管理路径：' + str(part))

    def validate_roots(self):
        for path in (self.root, self.run, self.base, self.busy, self.disabled):
            self.safe_path(path)
        if str(self.root) in ('/', '/etc', '/usr', '/var', '/tmp', '/home', '/run'):
            raise UninstallError('拒绝危险的安装根目录。')
        if not self.root.is_dir() or not self.run.is_dir():
            raise UninstallError('安装根目录或运行目录不存在。')
        if self.base.exists() and self.base.stat().st_uid != os.geteuid():
            raise UninstallError('管理目录不是当前用户所有，拒绝卸载。')

    def read_cron(self):
        try:
            result = subprocess.run(['crontab', '-l'], stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, universal_newlines=True,
                                    env=dict(os.environ, LC_ALL='C'), timeout=15)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise UninstallError('无法读取 crontab，未卸载：' + str(exc))
        if result.returncode == 0:
            return result.stdout
        if result.returncode == 1 and re.search(r'no crontab for\b', result.stderr, re.I):
            return ''
        raise UninstallError('读取 crontab 失败，不能当作没有任务：' + result.stderr.strip())

    def owns_cron_line(self, line):
        try:
            parts = shlex.split(line, comments=True)
        except ValueError:
            return False
        if not parts or parts[0].startswith('#'):
            return False
        command = parts[1:] if parts[0].startswith('@') else parts[5:]
        if command and command[0] in ('sh', 'bash', '/bin/sh', '/bin/bash', '/usr/bin/bash'):
            command = command[1:]
        if len(command) < 2:
            return False
        if command[0] in (str(self.base / 'dynamic_ip_cert.sh'), str(self.root / 'dynamic_ip_cert.sh')):
            return command[1] in tuple(str(self.base / ('dynamic-ip-v%d.conf' % n)) for n in (4, 6))
        if command[0] in (str(self.base / 'remote/remote_ip_ssl.sh'), str(self.root / 'remote_ip_ssl.sh')):
            return len(command) >= 3 and command[1] in ('cron', 'check') and bool(re.fullmatch(r'[A-Za-z0-9_.-]+', command[2]))
        return False

    def filter_cron(self, content):
        return ''.join(line for line in content.splitlines(keepends=True) if not self.owns_cron_line(line))

    def plan(self, purge):
        self.validate_roots()
        files = []
        for path, signature in self.scripts.items():
            self.safe_path(path)
            if path.exists():
                if not path.is_file() or signature not in path.read_text(errors='replace'):
                    raise UninstallError('同名文件无法确认属于本项目，保留并中止：' + str(path))
                files.append(path)
        if purge:
            for family in (4, 6):
                for suffix in ('conf', 'state', 'log'):
                    path = self.base / ('dynamic-ip-v%d.%s' % (family, suffix))
                    self.safe_path(path)
                    if path.is_file():
                        files.append(path)
            # Remote certificate copies deliberately remain: shared acme.sh may
            # still reference them. Never source device configuration as code.
            for directory, suffixes in ((self.base / 'remote/devices', ('.conf', '.state')),
                                        (self.base / 'remote/logs', ('.log',))):
                self.safe_path(directory)
                if directory.is_dir():
                    for path in directory.iterdir():
                        if path.suffix in suffixes:
                            self.safe_path(path)
                            if path.is_file():
                                files.append(path)
        return sorted(set(files))

    def active_processes(self):
        ignored = {os.getpid()}
        pid = os.getppid()
        # The initiating menu is an ancestor and must exit after successful removal.
        while pid > 1 and pid not in ignored:
            ignored.add(pid)
            try:
                status = Path('/proc/%d/status' % pid).read_text()
                pid = int(re.search(r'^PPid:\s+(\d+)', status, re.M).group(1))
            except (OSError, AttributeError):
                break
        targets = set(map(str, self.scripts)) | {str(self.root / '.acme.sh/acme.sh')}
        active = []
        for proc in Path('/proc').iterdir():
            if not proc.name.isdigit() or int(proc.name) in ignored:
                continue
            try:
                argv = (proc / 'cmdline').read_bytes().decode(errors='replace').split('\0')
            except FileNotFoundError:
                continue
            except PermissionError:
                raise UninstallError('无法核查运行中的进程，请用 root 执行。')
            if targets.intersection(argv):
                active.append(proc.name)
        return active

    def execute(self, purge, output=print):
        files = self.plan(purge)
        before = self.read_cron()
        filtered = self.filter_cron(before)
        active = self.active_processes()
        if active:
            raise UninstallError('仍有证书/管理进程运行（PID ' + ', '.join(active) + '），请等其结束；不会强杀。')
        lock_path = self.run / 'ssl-renewal-server-uninstall.lock'
        self.safe_path(lock_path)
        with lock_path.open('a') as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise UninstallError('另一个卸载操作正在运行。')
            self.base.mkdir(mode=0o700, exist_ok=True)
            if self.busy.exists():
                raise UninstallError('发现未完成卸载标记，请先核查 ' + str(self.busy))
            self.busy.write_text(str(os.getpid()) + '\n')
            self.busy.chmod(0o600)
            try:
                active = self.active_processes()
                if active:
                    raise UninstallError('有新证书进程启动，本次未卸载，请重试。')
                backup_root = self.root / 'ssl-renewal-backups'
                self.safe_path(backup_root)
                backup_root.mkdir(mode=0o700, exist_ok=True)
                backup_root.chmod(0o700)
                backup = Path(tempfile.mkdtemp(prefix='server-', dir=str(backup_root)))
                (backup / 'crontab.before').write_text(before)
                (backup / 'crontab.before').chmod(0o600)
                for path in files:
                    dest = backup / path.relative_to(self.root)
                    dest.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    shutil.copy2(str(path), str(dest))
                    dest.chmod(0o600)
                # A concurrent edit must never be replaced by our old snapshot.
                if self.read_cron() != before:
                    raise UninstallError('crontab 已被其他程序修改，未替换，请重试。')
                if filtered != before:
                    result = subprocess.run(['crontab', '-'], input=filtered, universal_newlines=True,
                                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
                    if result.returncode:
                        raise UninstallError('移除定时任务失败，文件保留：' + result.stderr.strip())
                # Persistent stop marker protects any queued old wrapper. The
                # installer clears it on an explicitly requested reinstall.
                self.disabled.touch(mode=0o600)
                for path in files:
                    self.safe_path(path)
                    unlink_existing(path)
                # Never delete a shared/unknown directory or a running lock inode.
                for directory in (self.base / 'remote/devices', self.base / 'remote/logs'):
                    if directory.is_dir() and not any(directory.iterdir()):
                        directory.rmdir()
                output('卸载完成。备份目录：' + str(backup))
                output('保留服务器证书/私钥、共享 ~/.acme.sh 及其续期任务、SSH 密钥和系统依赖。')
                output('本项目动态检测和旧远程任务已移除；不连接或卸载远端设备。')
                output('重新执行原安装命令即可安装；原有配置需重新开通对应任务。')
                return backup
            finally:
                unlink_existing(self.busy)


def main():
    if os.geteuid() != 0:
        print('请使用 root 卸载。', file=sys.stderr)
        return 1
    if Path('/etc/openwrt_release').exists():
        print('请使用 OpenWrt 本机菜单的卸载入口。', file=sys.stderr)
        return 1
    manager = ServerUninstaller()
    os.umask(0o077)
    print('\n============ 服务器卸载 ============')
    print('1）卸载程序（保留证书和配置）【默认】')
    print('2）备份后清理本项目配置并卸载（服务器证书保留）')
    print('0）取消')
    try:
        choice = input('请选择 [1]：').strip() or '1'
        if choice == '0':
            return 2
        if choice not in ('1', '2'):
            print('无效选项，未卸载。')
            return 2
        files = manager.plan(choice == '2')
        cron = manager.read_cron()
        print('将删除以下本项目文件（删除前备份）：')
        for path in files:
            print('  ' + str(path))
        print('将移除本项目动态/旧远程任务：%d 条' % sum(manager.owns_cron_line(line) for line in cron.splitlines()))
        print('不会删除 /root/*.crt、*.key 或 ~/.acme.sh；旧版无归属记录的证书也保留。')
        print('不会卸载软件包，不重启网站，不关闭防火墙，不撤销证书。')
        token = 'PURGE' if choice == '2' else 'UNINSTALL'
        if input('输入 %s 确认（回车取消）：' % token).strip() != token:
            print('已取消，未卸载。')
            return 2
        manager.execute(choice == '2')
        return 0
    except EOFError:
        print('已取消，未卸载。')
        return 2
    except (UninstallError, OSError, subprocess.TimeoutExpired) as exc:
        print('卸载未完成：' + str(exc), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
