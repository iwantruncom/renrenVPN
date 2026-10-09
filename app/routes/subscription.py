"""Token-authenticated subscription endpoints for browsers and VPN clients."""

import io
import functools
import hmac
import threading
import time
from collections import defaultdict, deque

import qrcode
from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response, StreamingResponse
from itsdangerous import BadSignature

from .. import db, links, singbox, system_ops
from ..web import (NotFound, current_user, guide_code, guide_serializer,
                   guide_url, preview_mode, sub_url, templates)

router = APIRouter()

# Subscription URLs contain bearer tokens; suppress Referer on external navigation.
SUB_HEADERS = {'Referrer-Policy': 'no-referrer', 'Cache-Control': 'no-store'}
RATE_WINDOW = 60
TOKEN_RATE = 120
QR_RATE = 30
GUIDE_SESSION_AGE = 3600
_RATE = defaultdict(deque)
_RATE_LOCK = threading.Lock()
_QR_SLOTS = threading.BoundedSemaphore(4)


def _rate_limit(request, token, limit=TOKEN_RATE, bucket='sub'):
    now = time.monotonic()
    ip = request.client.host if request.client else 'unknown'
    with _RATE_LOCK:
        cutoff = now - RATE_WINDOW
        for old_key in list(_RATE):
            values = _RATE[old_key]
            while values and values[0] < cutoff:
                values.popleft()
            if not values:
                del _RATE[old_key]
        keys = (((bucket, token, ip), limit), ((bucket, '*', ip), limit * 2))
        if any(len(_RATE[key]) >= key_limit for key, key_limit in keys):
            raise HTTPException(429, '请求太频繁，请稍后再试。')
        for key, _key_limit in keys:
            _RATE[key].append(now)


@functools.lru_cache(maxsize=128)
def _qr_bytes(payload):
    buf = io.BytesIO()
    qrcode.make(payload).save(buf, format='PNG')
    return buf.getvalue()


def _wants_html(request):
    """Select the HTML guide or client configuration from request metadata."""
    if request.query_params.get('page'):
        return True
    if request.query_params.get('raw'):
        return False
    return 'text/html' in request.headers.get('accept', '')


def _userinfo_header(client):
    # Report real usage only; total/expire stay 0 (unlimited, no expiry) since quotas are out of scope.
    t = db.all_traffic().get(client['name'], {})
    return (f"upload={t.get('uplink', 0)}; download={t.get('downlink', 0)}; "
            'total=0; expire=0')


def _singbox_profile_response(client):
    # Pin the server certificate key in the full profile; previews may lack a certificate.
    key_pin = '' if preview_mode() else singbox.cert_public_key_pin()
    if not key_pin and not preview_mode():
        # Never hand out a profile that skips server verification; clients keep the old one.
        return Response('服务器证书暂时无法读取，请稍后刷新订阅。', status_code=503,
                        media_type='text/plain; charset=utf-8', headers=SUB_HEADERS)
    return JSONResponse(links.singbox_profile(client, db.all_settings(), key_pin), headers={
        'Subscription-Userinfo': _userinfo_header(client),
        'Profile-Update-Interval': '12',
        'Profile-Title': links.profile_title_header(client),
        **SUB_HEADERS,
    })


def _guide_context(request, client):
    url = sub_url(request, client)
    settings = db.all_settings()
    pin = '' if preview_mode() else singbox.cert_pin()
    detected = links.detect_platform(request.headers.get('user-agent', ''))
    return {
        'request': request,
        'client': client,
        'sub_url': url,
        'deep_links': links.deep_links(url),
        'platforms': sorted(links.PLATFORMS, key=lambda p: p.key != detected),
        'downloads': links.DOWNLOADS,
        'platform_help_url': links.PLATFORM_HELP_URL,
        'detected': detected,
        'connections': links.client_links(client, settings, pin),
        'connection_methods': links.connection_card_links(client, settings, pin, preview_mode()),
    }


def _guide_unlocked(request, token):
    if current_user(request):
        return True
    cookie = request.cookies.get('renrenvpn_guide')
    if not cookie:
        return False
    try:
        data = guide_serializer.loads(cookie)
        return (data.get('token') == token
                and 0 <= time.time() - int(data.get('iat', 0)) < GUIDE_SESSION_AGE)
    except (BadSignature, TypeError, ValueError):
        return False


@router.get('/guide/{token}')
def guide_page(request: Request, token: str):
    client = db.get_client_by_guide_token(token)
    if not client or not client['enabled']:
        raise NotFound()
    if not _guide_unlocked(request, token):
        return templates.TemplateResponse('guide-access.html', {
            'request': request, 'error': '', 'guide_path': f'/guide/{token}',
        }, headers=SUB_HEADERS)
    return templates.TemplateResponse('howto.html', _guide_context(request, client),
                                      headers=SUB_HEADERS)


@router.post('/guide/{token}')
def guide_unlock(request: Request, token: str, code: str = Form(...)):
    _rate_limit(request, token, 5, 'guide')
    client = db.get_client_by_guide_token(token)
    if not client or not client['enabled']:
        raise NotFound()
    supplied = code.strip().replace(' ', '').upper()
    if not hmac.compare_digest(supplied, guide_code(client)):
        return templates.TemplateResponse('guide-access.html', {
            'request': request, 'error': '访问码不正确。', 'guide_path': f'/guide/{token}',
        }, status_code=401, headers=SUB_HEADERS)
    session = guide_serializer.dumps({'token': token, 'iat': int(time.time())})
    response = RedirectResponse(f'/guide/{token}', 303, headers=SUB_HEADERS)
    response.set_cookie('renrenvpn_guide', session, max_age=GUIDE_SESSION_AGE,
                        path=f'/guide/{token}', httponly=True, samesite='strict',
                        secure=system_ops.is_secure(request))
    return response


@router.get('/sub/{token}')
def subscription(request: Request, token: str):
    _rate_limit(request, token)
    client = db.get_client_by_token(token)
    if not client or not client['enabled']:
        # Subscription clients may parse any response body as configuration.
        raise NotFound()
    if _wants_html(request):
        return RedirectResponse(guide_url(request, client), 303, headers=SUB_HEADERS)
    # sing-box based clients (matched by UA prefix) receive the full JSON profile.
    if links.wants_singbox_json(request.headers.get('user-agent', '')):
        return _singbox_profile_response(client)
    body = links.subscription_body(client)
    return Response(body, media_type='text/plain; charset=utf-8', headers={
        'Subscription-Userinfo': _userinfo_header(client),
        'Profile-Update-Interval': '12',          # Hours.
        'Profile-Title': links.profile_title_header(client),
        'Profile-Web-Page-Url': guide_url(request, client),
        **SUB_HEADERS,
    })


@router.head('/sub/{token}')
def subscription_head(request: Request, token: str):
    """Support clients that probe subscription availability with HEAD."""
    client = db.get_client_by_token(token)
    if not client or not client['enabled']:
        raise NotFound()
    _rate_limit(request, token)
    return Response(status_code=200, headers=SUB_HEADERS)


@router.get('/sub/{token}/singbox.json')
def subscription_singbox(request: Request, token: str):
    """Return a full sing-box profile with client-side IPv6 routing rules."""
    _rate_limit(request, token)
    client = db.get_client_by_token(token)
    if not client or not client['enabled']:
        raise NotFound()
    return _singbox_profile_response(client)


@router.get('/sub/{token}/qr.png')
def subscription_qr(request: Request, token: str, p: str = ''):
    """Render a subscription QR code or a protocol-specific connection QR code."""
    _rate_limit(request, token, QR_RATE, 'qr')
    client = db.get_client_by_token(token)
    if not client or not client['enabled']:
        raise NotFound()
    if p == 'singbox':
        payload = sub_url(request, client).rstrip('/') + '/singbox.json'
    elif p in ('vless-reality', 'hysteria2') and p in singbox.enabled_keys():
        pin = '' if preview_mode() else singbox.cert_pin()
        if p == 'hysteria2' and not pin and not preview_mode():
            raise HTTPException(503, '证书指纹暂不可用，无法生成弱网连接二维码。')
        payload = links.share_link(p, client, db.all_settings(), pin)
    elif not p:
        payload = sub_url(request, client)
    else:
        raise NotFound()
    if not _QR_SLOTS.acquire(blocking=False):
        raise HTTPException(503, '二维码生成繁忙，请稍后重试。')
    try:
        data = _qr_bytes(payload)
    finally:
        _QR_SLOTS.release()
    return Response(data, media_type='image/png', headers=SUB_HEADERS)
