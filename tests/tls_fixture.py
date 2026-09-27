#!/usr/bin/env python3
"""Real loopback TLS fixture; no public listener, router or production CA access."""
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import subprocess
import sys
import time


def stop(base):
    pidfile = base / 'tls.pid'
    if not pidfile.exists():
        return
    pid = int(pidfile.read_text())
    try:
        cmdline = Path('/proc/%s/cmdline' % pid).read_bytes()
        if str(Path(__file__).resolve()).encode() in cmdline and str(base).encode() in cmdline:
            os.kill(pid, signal.SIGTERM)
            for _ in range(100):
                if not pidfile.exists():
                    break
                time.sleep(.01)
    except (ProcessLookupError, FileNotFoundError):
        pass
    pidfile.unlink(missing_ok=True)


def serve(base):
    db = json.loads((base / 'uci.json').read_text())
    endpoint = db['uhttpd.main.listen_https'].split()[0]
    host, port = endpoint.rsplit(':', 1)
    if host != '127.0.0.1':
        raise RuntimeError('test fixture must bind loopback only')
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(db['uhttpd.main.cert'], db['uhttpd.main.key'])
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((host, int(port)))
    listener.listen(8)
    (base / 'tls.pid').write_text(str(os.getpid()))
    (base / 'tls.ready').touch()
    def finish(*_):
        listener.close()
        (base / 'tls.pid').unlink(missing_ok=True)
        raise SystemExit(0)
    signal.signal(signal.SIGTERM, finish)
    try:
        while True:
            sock, _ = listener.accept()
            sock.settimeout(2)
            try:
                with context.wrap_socket(sock, server_side=True) as stream:
                    stream.recv(4096)
            except (ssl.SSLError, OSError):
                sock.close()
    finally:
        listener.close()


def restart(base):
    stop(base)
    (base / 'tls.ready').unlink(missing_ok=True)
    db = json.loads((base / 'uci.json').read_text())
    if not all(Path(db.get(k, '/missing')).is_file() for k in ('uhttpd.main.cert', 'uhttpd.main.key')):
        return 0
    if not db.get('uhttpd.main.listen_https'):
        return 0
    with (base / 'tls.stderr').open('w') as err:
        child = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), 'serve', str(base)],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=err, close_fds=False)
    for _ in range(100):
        if (base / 'tls.ready').exists():
            return 0
        if child.poll() is not None:
            return 1
        time.sleep(.02)
    child.terminate()
    child.wait(timeout=3)
    return 1


if __name__ == '__main__':
    mode, directory = sys.argv[1:]
    base = Path(directory).resolve()
    if mode == 'serve':
        serve(base)
    elif mode == 'restart':
        sys.exit(restart(base))
    elif mode == 'stop':
        stop(base)
    else:
        raise SystemExit('unknown fixture command')
