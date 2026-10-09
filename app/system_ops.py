"""System operations and bootstrap settings.

settings.json contains values required before database initialization. Runtime
application settings are stored in the database.
"""

import ipaddress
import json
import os
import re
import secrets
import socket
import subprocess
from pathlib import Path
from shutil import which

DATA_ROOT = Path(os.environ.get('IVPN_DATA_DIR', '/etc/freedom-vpn'))
WEB_SETTINGS = DATA_ROOT / 'web' / 'settings.json'
HELPER_SOCKET = os.environ.get('IVPN_HELPER_SOCKET', '/run/iwantrun-vpn/helper.sock')
HOST_LABEL_RE = re.compile(r'^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$')
ASSET_PATH_RE = re.compile(r'^assets-[A-Za-z0-9]{32}$')
_FALLBACK_ASSET_PATH = 'assets-' + os.urandom(16).hex()


def canonical_host(value):
    raw = str(value or '').strip()
    # Permit the preview placeholder while rejecting other invalid hostnames.
    if raw == 'SERVER_IP':
        return raw
    if raw.startswith('['):
        if not raw.endswith(']'):
            raise ValueError('服务器地址格式不正确')
        raw = raw[1:-1]
    if not raw:
        raise ValueError('服务器地址不能为空')
    try:
        return ipaddress.ip_address(raw).compressed
    except ValueError:
        host = raw.rstrip('.').lower()
        if len(host) > 253 or not all(HOST_LABEL_RE.fullmatch(label or '')
                                      for label in host.split('.')):
            raise ValueError('服务器地址格式不正确')
        return host


def authority(host, port=None):
    canonical = canonical_host(host)
    rendered = f'[{canonical}]' if ':' in canonical else canonical
    return rendered if port is None else f'{rendered}:{int(port)}'


def canonical_public_ipv4(value):
    """Require a public IPv4 address for the supported IP certificate profile."""
    host = canonical_host(value)
    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ValueError('当前版本只支持服务器公网 IPv4，暂不支持域名') from exc
    if address.version != 4:
        raise ValueError('当前版本只支持服务器公网 IPv4')
    return address.compressed


def privileged_action(payload):
    """Request an allowlisted operation from the privileged helper."""
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(35)
    try:
        client.connect(HELPER_SOCKET)
        client.sendall(json.dumps(payload, separators=(',', ':')).encode() + b'\n')
        client.shutdown(socket.SHUT_WR)
        data = bytearray()
        while b'\n' not in data:
            chunk = client.recv(4096)
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > 64 * 1024:
                raise RuntimeError('root helper 返回内容异常过大')
    except OSError as exc:
        raise RuntimeError(f'无法连接权限助手：{exc}')
    finally:
        client.close()
    try:
        response = json.loads(bytes(data).split(b'\n', 1)[0])
    except (json.JSONDecodeError, IndexError) as exc:
        raise RuntimeError(f'权限助手响应损坏：{exc}')
    if not response.get('ok'):
        raise RuntimeError(response.get('error') or '权限助手执行失败')
    return response.get('result') or {}


def run_cmd(cmd, timeout=20):
    try:
        process = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return process.returncode, process.stdout.strip(), process.stderr.strip()
    except Exception as exc:
        return 1, '', str(exc)


def is_secure(request):
    if request.url.scheme == 'https':
        return True
    forwarded = request.headers.get('x-forwarded-proto', '')
    return forwarded.split(',')[0].strip().lower() == 'https'


def open_port(port, proto):
    """Open a host firewall port; cloud security-group rules remain external."""
    proto = proto.lower()
    port = int(port)
    if proto not in ('tcp', 'udp') or not 1 <= port <= 65535:
        return False
    if os.geteuid() != 0:
        return bool(privileged_action({
            'action': 'firewall', 'operation': 'add', 'port': port, 'proto': proto,
        }).get('changed'))
    changed = False
    if which('ufw'):
        code, out, err = run_cmd(['ufw', 'allow', f'{port}/{proto}'], 15)
        if code != 0:
            raise RuntimeError(err or out or 'ufw 放行端口失败')
        changed = True
    if which('firewall-cmd'):
        code, out, err = run_cmd(['firewall-cmd', '--permanent', f'--add-port={port}/{proto}'], 15)
        if code != 0:
            raise RuntimeError(err or out or 'firewalld 放行端口失败')
        code, out, err = run_cmd(['firewall-cmd', '--reload'], 15)
        if code != 0:
            raise RuntimeError(err or out or 'firewalld 重载失败')
        changed = True
    return changed


def close_port(port, proto):
    """Remove a host firewall rule, tolerating rules that are already absent."""
    proto = proto.lower()
    port = int(port)
    if proto not in ('tcp', 'udp') or not 1 <= port <= 65535:
        return False
    if os.geteuid() != 0:
        return bool(privileged_action({
            'action': 'firewall', 'operation': 'remove', 'port': port, 'proto': proto,
        }).get('changed'))
    changed = False
    if which('ufw'):
        code, out, err = run_cmd(['ufw', '--force', 'delete', 'allow', f'{port}/{proto}'], 15)
        if code != 0 and 'not exist' not in (out + err).lower():
            raise RuntimeError(err or out or 'ufw 收回端口失败')
        changed = True
    if which('firewall-cmd'):
        code, out, err = run_cmd(['firewall-cmd', '--permanent', f'--remove-port={port}/{proto}'], 15)
        if code != 0 and 'not enabled' not in (out + err).lower():
            raise RuntimeError(err or out or 'firewalld 收回端口失败')
        code, out, err = run_cmd(['firewall-cmd', '--reload'], 15)
        if code != 0:
            raise RuntimeError(err or out or 'firewalld 重载失败')
        changed = True
    return changed


def web_settings():
    # Only a missing file means "use defaults". An unreadable one must fail loudly:
    # falling back would serve the panel on 2083 at the public /login path.
    try:
        return json.loads(WEB_SETTINGS.read_text())
    except FileNotFoundError:
        return {}


def write_private_file(path, data, mode=0o600):
    """Atomically replace ``path`` inside the web-owned data tree.

    Root (SSH CLI, the helper) writes here too, so never follow links the web user
    could plant: open the directory without following it, create the temp file
    exclusively, give it to the directory owner (else the panel cannot read it), and
    rename within that same directory.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    dir_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    tmp = f'.{path.name}.{secrets.token_hex(8)}.tmp'
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode,
                     dir_fd=dir_fd)
        try:
            with os.fdopen(fd, 'wb') as output:
                # chmod before chown: once the file belongs to the web user, the helper
                # (no CAP_FOWNER in its sandbox) may no longer change its mode.
                os.fchmod(output.fileno(), mode)
                if os.geteuid() == 0:
                    owner = os.fstat(dir_fd)
                    os.fchown(output.fileno(), owner.st_uid, owner.st_gid)
                output.write(data)
            os.replace(tmp, path.name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        except BaseException:
            try:
                os.unlink(tmp, dir_fd=dir_fd)
            except OSError:
                pass
            raise
    finally:
        os.close(dir_fd)


def save_web_settings(values):
    merged = {**web_settings(), **values}
    write_private_file(WEB_SETTINGS, json.dumps(merged, ensure_ascii=False, indent=2).encode())
    return merged


def login_path():
    path = str(web_settings().get('login_path', 'login')).strip().strip('/')
    return path or 'login'


def asset_path():
    path = str(web_settings().get('asset_path', '')).strip().strip('/')
    return path if ASSET_PATH_RE.fullmatch(path) else _FALLBACK_ASSET_PATH


def panel_port():
    """Return the configured panel port, falling back to 2083 if unavailable."""
    try:
        return int(web_settings().get('panel_port', 2083))
    except (TypeError, ValueError):
        return 2083


# ACME HTTP-01 uses port 80; the panel itself does not listen on this port.
ACME_PORT = 80
