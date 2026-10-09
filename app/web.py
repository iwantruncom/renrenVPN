"""Shared web-layer services for templates, authentication, and presentation."""

import base64
import hashlib
import hmac
import os
import threading
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import quote

from fastapi import Form, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from itsdangerous import BadSignature, URLSafeSerializer, URLSafeTimedSerializer

from . import db, links, singbox, system_ops

BASE_DIR = Path(__file__).resolve().parent
SECRET_FILE = db.DATA_ROOT / 'web' / 'session.secret'
SECRET_FILE.parent.mkdir(parents=True, exist_ok=True)
if not SECRET_FILE.exists():
    SECRET_FILE.write_text(os.urandom(32).hex())
    SECRET_FILE.chmod(0o600)
SESSION_SECRET = SECRET_FILE.read_text().strip()
serializer = URLSafeSerializer(SESSION_SECRET, salt='renrenvpn-web')
guide_serializer = URLSafeSerializer(SESSION_SECRET, salt='renrenvpn-guide')
# Sign notices so a crafted ?msg= link cannot show attacker text in the panel's own banner.
notice_serializer = URLSafeTimedSerializer(SESSION_SECRET, salt='renrenvpn-notice')
NOTICE_MAX_AGE = 600

templates = Jinja2Templates(directory=str(BASE_DIR / 'templates'))


def session_max_age():
    try:
        return max(1, int(db.get_setting('session_days', '30'))) * 86400
    except ValueError:
        return 30 * 86400


def current_session(request):
    cookie = request.cookies.get('renrenvpn_session')
    if not cookie:
        return None
    try:
        data = serializer.loads(cookie)
    except BadSignature:
        return None
    if int(time.time()) - int(data.get('iat', 0)) > session_max_age():
        return None
    # Recheck the session epoch so CLI credential changes revoke active sessions.
    if int(data.get('ep', -1)) != db.get_session_epoch():
        return None
    return data


def current_user(request):
    data = current_session(request)
    return data.get('username') if data else None


def csrf_token(request):
    return (current_session(request) or {}).get('csrf', '')


class NotFound(Exception):
    pass


class RedirectException(Exception):
    def __init__(self, location):
        self.location = location


def require_user(request: Request) -> str:
    """Reject unauthenticated requests without disclosing the login path."""
    user = current_user(request)
    if not user:
        raise NotFound()
    return user


async def verify_csrf(request: Request, csrf_token_value: str = Form(..., alias='csrf_token')):
    expected = csrf_token(request)
    if not (expected and csrf_token_value and hmac.compare_digest(expected, csrf_token_value)):
        raise RedirectException(request.headers.get('referer') or '/')


def login_url():
    return '/' + system_ops.login_path()


def redirect_with_message(path, msg='', error=''):
    params = []
    if msg:
        params.append('msg=' + quote(notice_serializer.dumps(msg)))
    if error:
        params.append('error=' + quote(notice_serializer.dumps(error)))
    if not params:
        return RedirectResponse(path, 302)
    # Preserve any query string already present in the path.
    separator = '&' if '?' in path else '?'
    return RedirectResponse(path + separator + '&'.join(params), 302)


def notices(request):
    """Return the msg/error notices, dropping any value the server did not sign."""
    result = {}
    for key in ('msg', 'error'):
        try:
            value = notice_serializer.loads(request.query_params.get(key, ''),
                                            max_age=NOTICE_MAX_AGE)
        except BadSignature:
            value = ''
        result[key] = value if isinstance(value, str) else ''
    return result


LOGIN_WINDOW = 600
LOGIN_MAX_FAILURES = 10
# Bound distributed guessing; one IP alone still hits LOGIN_MAX_FAILURES first.
LOGIN_GLOBAL_MAX_FAILURES = 200
LOGIN_VERIFY_SLOTS = threading.BoundedSemaphore(4)


def login_blocked(ip, username=''):
    """Return whether the source IP or all sources together exceeded the failure limit.

    Keyed by IP rather than username so an attacker cannot lock out other administrators.
    """
    cutoff = datetime.fromtimestamp(time.time() - LOGIN_WINDOW).strftime('%Y-%m-%d %H:%M:%S')
    con = db.connect()
    row = con.execute(
        '''SELECT COALESCE(SUM(ip=?), 0), COUNT(*)
           FROM login_logs
           WHERE success=0 AND created_at>=?''',
        (ip, cutoff),
    ).fetchone()
    con.close()
    return (int(row[0] or 0) >= LOGIN_MAX_FAILURES
            or int(row[1] or 0) >= LOGIN_GLOBAL_MAX_FAILURES)


def record_login(username, ip, success):
    con = db.connect()
    con.execute(
        'INSERT INTO login_logs(username,ip,success,message,created_at) VALUES (?,?,?,?,?)',
        (username, ip, 1 if success else 0, 'login',
         datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
    )
    con.execute('DELETE FROM login_logs WHERE id <= (SELECT MAX(id) - 500 FROM login_logs)')
    con.commit()
    con.close()


def preview_mode():
    return os.environ.get('IVPN_PREVIEW') == '1'


def apply_config():
    """Render and apply the sing-box configuration; no-op in preview mode."""
    if preview_mode():
        return
    singbox.apply()


def sub_base(request):
    """Use the panel HTTPS origin for subscription URLs.

    The request origin is used only before a public host has been configured.
    """
    host = db.get_setting('public_host')
    if not host:
        return str(request.base_url).rstrip('/')
    port = system_ops.panel_port()
    return f'https://{system_ops.authority(host)}' if port == 443 \
        else f'https://{system_ops.authority(host, port)}'


def sub_url(request, client):
    return f"{sub_base(request)}/sub/{client['sub_token']}"


def guide_url(request, client):
    return f"{sub_base(request)}/guide/{client['guide_token']}"


def guide_code(client):
    digest = hmac.new(SESSION_SECRET.encode(),
                      f"guide:{client['guide_token']}".encode(), hashlib.sha256).digest()
    return base64.b32encode(digest[:8]).decode().rstrip('=')


def human_bytes(count):
    count = float(count or 0)
    for unit in ('B', 'KB', 'MB', 'GB'):
        if count < 1024 or unit == 'GB':
            return f'{count:.0f} {unit}' if unit == 'B' else f'{count:.1f} {unit}'
        count /= 1024


# Use a three-minute window to tolerate missed one-minute samples.
ONLINE_WINDOW = 180


def seconds_since(stamp):
    """Return elapsed seconds, or None for a missing or invalid timestamp."""
    if not stamp:
        return None
    try:
        return max(0.0, (datetime.now()
                         - datetime.strptime(stamp, '%Y-%m-%d %H:%M:%S')).total_seconds())
    except ValueError:
        return None


def recently_active(stamp):
    """Return whether traffic was recorded within the online window."""
    elapsed = seconds_since(stamp)
    return elapsed is not None and elapsed < ONLINE_WINDOW


def traffic_overview(clients, traffic):
    """Summarize persisted usage for clients that still exist."""
    usage = [traffic.get(client['name'], {}) for client in clients]
    return {
        'recent_count': sum(
            client['enabled'] and recently_active(record.get('last_seen'))
            for client, record in zip(clients, usage)
        ),
        'uplink': sum(record.get('uplink') or 0 for record in usage),
        'downlink': sum(record.get('downlink') or 0 for record in usage),
    }


def home_clients(clients, traffic):
    """Build lightweight dashboard rows, without links or the certificate pin."""
    rows = []
    for client in clients:
        used = traffic.get(client['name'], {})
        total = (used.get('uplink') or 0) + (used.get('downlink') or 0)
        rows.append({
            'id': client['id'], 'name': client['name'], 'enabled': client['enabled'],
            'traffic': human_bytes(total) if total else '',
            'last_seen': human_since(used.get('last_seen')),
            'online': bool(client['enabled']) and recently_active(used.get('last_seen')),
        })
    return rows


def human_since(stamp):
    """Format elapsed time for display; omit invalid timestamps."""
    seconds = seconds_since(stamp)
    if seconds is None:
        return ''
    for limit, div, unit in ((3600, 60, '分钟'), (86400, 3600, '小时'), (None, 86400, '天')):
        if limit is None or seconds < limit:
            value = int(seconds // div)
            return '刚刚' if value < 1 else f'{value} {unit}前'


def client_rows(request):
    settings = db.all_settings()
    pin = '' if preview_mode() else singbox.cert_pin()
    traffic = db.all_traffic()
    rows = []
    for client in db.list_clients():
        url = sub_url(request, client)
        used = traffic.get(client['name'], {})
        total = (used.get('uplink') or 0) + (used.get('downlink') or 0)
        last_seen = used.get('last_seen')
        rows.append({
            **client,
            'sub_url': url,
            'guide_url': guide_url(request, client),
            'guide_code': guide_code(client),
            'connections': links.client_links(client, settings, pin),
            'connection_methods': links.connection_card_links(client, settings, pin, preview_mode()),
            'traffic': human_bytes(total) if total else '',
            'uplink': human_bytes(used.get('uplink') or 0) if total else '',
            'downlink': human_bytes(used.get('downlink') or 0) if total else '',
            'last_seen': human_since(last_seen),
            # Determine online state from the collection timestamp, not display text.
            'online': bool(client['enabled']) and recently_active(last_seen),
        })
    return rows
