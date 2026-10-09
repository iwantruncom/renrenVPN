"""Serve the panel and subscriptions over a validated HTTPS endpoint."""

import asyncio
import os

import uvicorn

from . import db, singbox
from .system_ops import panel_port, run_cmd

# Sample traffic once per minute; online status uses a three-minute window.
STATS_INTERVAL = 60

PANEL_CERT = db.DATA_ROOT / 'web' / 'panel-cert-current' / 'fullchain.pem'
PANEL_KEY = db.DATA_ROOT / 'web' / 'panel-cert-current' / 'key.pem'


def ensure_panel_cert():
    """Require a valid, publicly issued certificate matching the panel host."""
    if not (PANEL_CERT.is_file() and PANEL_KEY.is_file()):
        raise RuntimeError('缺少可信面板证书；请运行安装器或证书续期服务')
    host = db.get_setting('public_host') or ''
    checks = [
        ['openssl', 'x509', '-in', str(PANEL_CERT), '-checkend', '86400', '-noout'],
        ['openssl', 'x509', '-in', str(PANEL_CERT),
         '-checkip' if host.replace('.', '').isdigit() or ':' in host else '-checkhost',
         host, '-noout'],
    ]
    for command in checks:
        code, out, err = run_cmd(command, 15)
        if code != 0:
            raise RuntimeError(err or out or '面板证书身份或有效期检查失败')
    _, subject, _ = run_cmd(['openssl', 'x509', '-in', str(PANEL_CERT),
                              '-noout', '-subject', '-nameopt', 'RFC2253'], 10)
    _, issuer, _ = run_cmd(['openssl', 'x509', '-in', str(PANEL_CERT),
                             '-noout', '-issuer', '-nameopt', 'RFC2253'], 10)
    if subject.partition('=')[2] == issuer.partition('=')[2]:
        raise RuntimeError('面板证书是自签证书，拒绝开放密码登录')
    cert_code, cert_public, cert_error = run_cmd(
        ['openssl', 'x509', '-in', str(PANEL_CERT), '-pubkey', '-noout'], 10)
    key_code, key_public, key_error = run_cmd(
        ['openssl', 'pkey', '-in', str(PANEL_KEY), '-pubout'], 10)
    if cert_code or key_code or cert_public != key_public:
        raise RuntimeError(cert_error or key_error or '面板证书和私钥不匹配')
    PANEL_KEY.chmod(0o600)


class _Server(uvicorn.Server):
    # Avoid competing signal handlers; systemd terminates the process with SIGTERM.
    def install_signal_handlers(self):
        pass


def main():
    ensure_panel_cert()
    # Share HTTPS between the panel and subscriptions; reserve port 80 for ACME renewal.
    # Disable access logs because subscription URLs contain bearer tokens.
    common = {'host': '0.0.0.0', 'access_log': False, 'server_header': False}
    servers = [
        _Server(uvicorn.Config('app.main:app', port=panel_port(),
                               ssl_certfile=str(PANEL_CERT), ssl_keyfile=str(PANEL_KEY),
                               **common)),
    ]

    async def collect_forever():
        """Persist sing-box traffic counters on a single process-level schedule."""
        while True:
            await asyncio.sleep(STATS_INTERVAL)
            try:
                await asyncio.to_thread(singbox.collect_stats)
            except Exception:
                pass

    async def run_all():
        tasks = [s.serve() for s in servers]
        if os.environ.get('IVPN_PREVIEW') != '1':
            tasks.append(collect_forever())
        await asyncio.gather(*tasks)

    asyncio.run(run_all())


if __name__ == '__main__':
    main()
