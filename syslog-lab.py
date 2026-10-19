#!/usr/bin/env python3
"""Manage a Debian rsyslog lab receiver; never stop local system logging."""
import argparse
import grp
import ipaddress
import json
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone

BASE = Path(__file__).resolve().parent
CONF = Path('/etc/rsyslog.d/10-gns3.conf')
LOGS = Path('/var/log/remote')
STATE = Path('/var/lib/syslog-lab')
MARK = '# Managed by syslog-lab\n'


def run(*args, **kwargs):
    return subprocess.run(args, check=True, text=True, **kwargs)


def settings():
    c = json.loads((BASE / 'config.json').read_text())
    ipaddress.IPv4Address(c['server_ip'])
    if not isinstance(c['port'], int) or not 1 <= c['port'] <= 65535:
        raise ValueError('port must be 1..65535')
    pwd.getpwnam(c['reader_user'])
    for k in ('clear_logs_on_start', 'archive_before_clear'):
        if type(c[k]) is not bool:
            raise ValueError(k + ' must be true or false')
    return c


def validate():
    run('/usr/sbin/rsyslogd', '-N1')


def restart():
    run('systemctl', 'restart', 'rsyslog')


def atomic_write(path, content):
    fd, name = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as f:
            f.write(content)
        os.chmod(name, 0o644)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def safe_dir(path):
    if path.is_symlink() or (path.exists() and not path.is_dir()):
        raise ValueError(f'Unsafe directory: {path}')
    path.mkdir(parents=True, exist_ok=True)


def set_permissions():
    gid = grp.getgrnam('adm').gr_gid
    # Refuse symlinks so permission changes never reach outside the log tree.
    nodes = [LOGS, *LOGS.rglob('*')]
    if any(p.is_symlink() for p in nodes):
        raise ValueError('Symlink in /var/log/remote; refusing permission changes')
    for p in nodes:
        os.chown(p, -1, gid)
        os.chmod(p, 0o2750 if p.is_dir() else 0o640)


def start(c):
    for cmd in ('rsyslogd', 'tcpdump'):
        if not shutil.which(cmd) and not Path('/usr/sbin', cmd).exists():
            raise ValueError('Install dependencies: sudo apt install rsyslog tcpdump')
    data = json.loads(run('ip', '-j', '-4', 'address', 'show', 'dev', c['interface'],
                          capture_output=True).stdout)
    if not any(a['local'] == c['server_ip'] for d in data for a in d['addr_info']):
        raise ValueError('server_ip is not assigned to the selected interface')
    safe_dir(STATE)
    safe_dir(LOGS)
    if CONF.is_symlink():
        raise ValueError('Refusing symlink config')
    old = CONF.read_text() if CONF.exists() else None
    if old and not old.startswith(MARK):
        # Adopt only the configuration from this lab, after retaining its original.
        required = ('name="RemoteByHostProgram"', 'ruleset(name="gns3")',
                    '/var/log/remote/', 'type="imudp"')
        if not all(x in old for x in required):
            raise ValueError('10-gns3.conf is unfamiliar; refusing to overwrite it')
        backup = STATE / '10-gns3.original.conf'
        if not backup.exists():
            atomic_write(backup, old)
    grp.getgrnam('adm')
    user = pwd.getpwnam(c['reader_user'])
    run('usermod', '-aG', 'adm', user.pw_name)
    set_permissions()
    content = MARK + '''module(load="imudp")

template(name="RemoteByHostProgram" type="string"
 string="/var/log/remote/%hostname:::secpath-replace%/%programname:::secpath-replace%.log")
ruleset(name="gns3") {
 action(type="omfile" dynaFile="RemoteByHostProgram"
  template="RSYSLOG_FileFormat" createDirs="on"
  fileGroup="adm" dirGroup="adm"
  dirCreateMode="02750" fileCreateMode="0640")
}
''' + f'input(type="imudp" address="{c["server_ip"]}" port="{c["port"]}" ruleset="gns3")\n'
    try:
        atomic_write(CONF, content)
        validate()
        if c['clear_logs_on_start']:
            # Close remote file handles before archiving and clearing.
            CONF.unlink()
            validate()
            restart()
            if any(LOGS.iterdir()):
                if c['archive_before_clear']:
                    archives = STATE / 'archives'
                    safe_dir(archives)
                    os.chmod(archives, 0o700)
                    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
                    archive = archives / f'remote-{stamp}.tar.gz'
                    run('tar', '-czf', str(archive), '-C', str(LOGS), '.')
                    os.chmod(archive, 0o600)
                    print('Archive:', archive)
                for p in LOGS.iterdir():
                    if p.is_dir() and not p.is_symlink():
                        shutil.rmtree(p)
                    else:
                        p.unlink()
            atomic_write(CONF, content)
        run('systemctl', 'enable', 'rsyslog')
        restart()
        run('systemctl', 'is-active', '--quiet', 'rsyslog')
        run('ss', '-lunp', f'sport = :{c["port"]}')
    except BaseException:
        if old is None:
            CONF.unlink(missing_ok=True)
        else:
            atomic_write(CONF, old)
        try:
            validate()
            restart()
        except Exception as e:
            print('Rollback restart failed:', e)
        raise
    print(f'Receiver enabled: {c["server_ip"]}:{c["port"]}/UDP')
    print('Logs: /var/log/remote/<hostname>/<programname>.log')
    print('For read access and Tab: log in again, or run newgrp adm in your terminal.')


def stop():
    if not CONF.exists():
        print('Lab receiver is already disabled.')
        return
    if CONF.is_symlink() or not CONF.read_text().startswith(MARK):
        raise ValueError('Config is not managed by this script; refusing to remove it')
    old = CONF.read_text()
    try:
        CONF.unlink()
        validate()
        restart()
    except BaseException:
        atomic_write(CONF, old)
        restart()
        raise
    print('Lab receiver disabled. Logs retained. Debian local logging remains active.')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=('start', 'stop', 'status', 'check'))
    args = parser.parse_args()
    if args.action == 'check':
        c = settings()
        print(json.dumps(c, indent=2, ensure_ascii=False))
        print('Configuration OK; no system changes made.')
        return
    if os.geteuid() != 0:
        raise ValueError('Run with sudo')
    # Serialize start/stop; do not depend on config.json when stopping.
    import fcntl
    with open('/run/lock/syslog-lab.lock', 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if args.action == 'start':
            start(settings())
        elif args.action == 'stop':
            stop()
        else:
            print('Managed receiver:', CONF.exists() and CONF.read_text().startswith(MARK))
            subprocess.run(['systemctl', 'is-active', 'rsyslog'], check=False)
            subprocess.run(['ss', '-lunp'], check=False)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError) as exc:
        raise SystemExit(f'Error: {exc}')
