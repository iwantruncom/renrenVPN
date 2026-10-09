"""Compose panel routes and handle dashboard, repair, and authentication.

The catch-all login route must be registered after application routes.
"""

import secrets
import sys
import time
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Request
from fastapi.responses import PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool

from . import db, links, singbox, system_ops
from .db import log_action, verify_admin
from .routes import settings as settings_routes
from .routes import downloads as download_routes, subscription, users
from .web import (BASE_DIR, NotFound, RedirectException, apply_config, csrf_token,
                  current_user, login_url, preview_mode, redirect_with_message, require_user,
                  serializer, session_max_age, sub_url, guide_url, templates, traffic_overview,
                  home_clients, notices, verify_csrf, human_bytes,
                  LOGIN_MAX_FAILURES, LOGIN_VERIFY_SLOTS, login_blocked, record_login)


@asynccontextmanager
async def lifespan(app):
    db.init_db()
    yield


# Disable public API documentation; it exposes route names and application metadata.
app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
STATIC_PATH = '/' + system_ops.asset_path()
# Downloads live under the random asset prefix so /download/* probes get the uniform 404.
# Registered before the static mount, which would otherwise shadow them.
app.include_router(download_routes.router, prefix=STATIC_PATH)
app.mount(STATIC_PATH, StaticFiles(directory=str(BASE_DIR / 'static')), name='static')
templates.env.globals['static_path'] = STATIC_PATH
templates.env.filters['download_href'] = (
    lambda url: STATIC_PATH + url if url.startswith('/download/') else url)


@app.middleware('http')
async def security_headers(request: Request, call_next):
    path = request.url.path
    public_request = (
        (path == login_url() and request.method in ('GET', 'POST'))
        or (path.startswith('/sub/') and request.method in ('GET', 'HEAD'))
        or (path.startswith('/guide/') and request.method in ('GET', 'POST'))
        or (path.startswith(STATIC_PATH + '/') and request.method in ('GET', 'HEAD'))
    )
    response = (await call_next(request) if current_user(request) or public_request
                else PlainTextResponse('Not Found', 404))
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
    response.headers['X-Robots-Tag'] = 'noindex, nofollow, noarchive'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; "
        "base-uri 'none'; form-action 'self'"
    )
    if not path.startswith(STATIC_PATH + '/'):
        # Prevent shared-device caching of credentials and subscription URLs.
        response.headers.setdefault('Cache-Control', 'no-store')
    if system_ops.is_secure(request):
        response.headers['Strict-Transport-Security'] = 'max-age=31536000'
    return response


@app.exception_handler(NotFound)
async def _not_found(request, exc):
    return PlainTextResponse('Not Found', 404)


@app.exception_handler(RedirectException)
async def _redirect(request, exc):
    return RedirectResponse(exc.location, 302)


@app.get('/')
def dashboard(request: Request, user: str = Depends(require_user)):
    settings = db.all_settings()
    clients = db.list_clients()
    active = [c for c in clients if c['enabled']]
    running = True if preview_mode() else singbox.service_running()
    traffic = db.all_traffic()
    usage = traffic_overview(clients, traffic)

    # Return to the second guide step after adding a user.
    guide = db.get_client(request.query_params.get('guide', ''))
    guide_data = None
    if guide:
        url = sub_url(request, guide)
        guide_data = {
            'name': guide['name'],
            'token': guide['sub_token'],
            'sub_url': url,
            'guide_url': guide_url(request, guide),
            'singbox_url': url.rstrip('/') + '/singbox.json',
            'deep_links': links.deep_links(url),
        }
    # Open the first-run guide once per installation, whatever browser the admin uses.
    first_visit = settings.get('guide_seen') != '1'
    if first_visit:
        db.set_setting('guide_seen', '1')
    platform_key = links.detect_platform(request.headers.get('user-agent', ''))
    my_platform = next((p for p in links.PLATFORMS if p.key == platform_key), None)

    return templates.TemplateResponse('dashboard.html', {
        'request': request,
        'active': 'home',
        'csrf_token': csrf_token(request),
        'running': running,
        # Reflect an unavailable REALITY target in the overall status.
        'ready': running and bool(active) and settings.get('reality_sni_ok') != '0',
        'client_count': len(clients),
        'active_count': len(active),
        'recent_count': usage['recent_count'],
        'traffic_total': human_bytes(usage['uplink'] + usage['downlink']),
        'traffic_uplink': human_bytes(usage['uplink']),
        'traffic_downlink': human_bytes(usage['downlink']),
        'has_traffic': bool(usage['uplink'] + usage['downlink']),
        'clients': home_clients(clients, traffic),
        'protocols': [singbox.BY_KEY[k] for k in singbox.enabled_keys(settings)],
        'firewall_rules': singbox.firewall_rules(settings),
        'panel_port': system_ops.panel_port(),
        'acme_port': system_ops.ACME_PORT,
        'guide': guide_data,
        'first_visit': first_visit,
        'sni_broken': settings.get('reality_sni_ok') == '0',
        'reality_sni': settings.get('reality_sni', ''),
        'server_host': settings.get('public_host', ''),
        'my_platform': my_platform,
        'downloads': links.DOWNLOADS,
        'platform_help_url': links.PLATFORM_HELP_URL,
        **notices(request),
    })


@app.post('/repair')
def repair(request: Request, user: str = Depends(require_user), _: None = Depends(verify_csrf)):
    """Regenerate the configuration and restart the service from persisted state."""
    try:
        # Replace an unavailable REALITY target before rebuilding the configuration.
        # Single-protocol links embed the target and must be redistributed; subscriptions refresh on their own.
        swapped, sni_ok = '', True
        if not preview_mode():
            old = db.get_setting('reality_sni', '')
            sni_ok = singbox.sni_usable(old)
            if not sni_ok:
                try:
                    picked = singbox.pick_sni()
                except Exception:
                    db.set_setting('reality_sni_ok', '0')
                    raise
                if singbox.sni_usable(picked):
                    sni_ok = True
                    if picked != old:
                        db.set_setting('reality_sni', picked)
                        swapped = picked
            db.set_setting('reality_sni_ok', '1' if sni_ok else '0')
        apply_config()
        if swapped:
            log_action('repair', 'auto sni', 'ok', swapped)
            return redirect_with_message('/', msg=(
                f'伪装域名连不上，已自动换成 {swapped} 并重启。用订阅链接的人 12 小时内'
                '自动恢复；手动导入过单条链接的人，需要把新链接重新发给他。'))
        if not sni_ok:
            return redirect_with_message(
                '/', error='服务已重启，但所有候选伪装域名都连不上，可能是服务器网络问题，稍后再点一次试试。'
                '也可以在设置页手动填一个。')
        return redirect_with_message('/', msg='已经重新检查并启动，连接恢复正常。')
    except Exception as exc:
        log_action('repair', 'singbox', 'error', str(exc))
        return redirect_with_message('/', error='修复没有成功。请稍后再试，或在服务器上运行 renrenvpn repair 查看原因。')


# Register application routes before the login catch-all.
app.include_router(users.router)
app.include_router(subscription.router)
app.include_router(settings_routes.router)


# Login and logout. The catch-all routes below must stay registered last.
@app.post('/logout')
def logout(request: Request, user: str = Depends(require_user),
           _: None = Depends(verify_csrf)):
    # Require authentication so the redirect never discloses the hidden login path (H-03).
    # Single admin: revoking every session also kills a copied cookie.
    db.bump_session_epoch()
    resp = RedirectResponse(login_url(), 302)
    resp.delete_cookie('renrenvpn_session')
    return resp


def _https_login_redirect(request):
    """Redirect an HTTP login request to the configured HTTPS port."""
    if preview_mode() or system_ops.is_secure(request):
        return None
    host = request.url.hostname or singbox.public_host()
    return RedirectResponse(
        f'https://{system_ops.authority(host, system_ops.panel_port())}{login_url()}', 302)


@app.get('/{path_name}')
def login_page(request: Request, path_name: str):
    if path_name != system_ops.login_path():
        raise NotFound()
    redirect = _https_login_redirect(request)
    if redirect:
        return redirect
    return templates.TemplateResponse('login.html', {
        'request': request, 'error': '', 'login_path': login_url()})


@app.post('/{path_name}')
async def login(request: Request, path_name: str):
    if path_name != system_ops.login_path():
        raise NotFound()
    redirect = _https_login_redirect(request)
    if redirect:
        return redirect
    form = await request.form()
    username = str(form.get('username') or '')
    password = str(form.get('password') or '')
    ip = request.client.host if request.client else ''
    if login_blocked(ip, username):
        return templates.TemplateResponse('login.html', {
            'request': request, 'login_path': login_url(),
            'error': '失败次数太多，请 10 分钟后再试。忘记密码可以在服务器上运行 renrenvpn reset-password。'})
    if not LOGIN_VERIFY_SLOTS.acquire(blocking=False):
        return PlainTextResponse('登录请求较多，请稍后重试。', status_code=429)
    try:
        ok = await run_in_threadpool(verify_admin, username, password)
        record_login(username, ip, ok)
    finally:
        LOGIN_VERIFY_SLOTS.release()
    if not ok:
        return templates.TemplateResponse('login.html', {
            'request': request, 'login_path': login_url(), 'error': '账号或密码不正确。'})
    session = serializer.dumps({
        'username': username,
        'csrf': secrets.token_urlsafe(32),
        'iat': int(time.time()),
        'ep': db.get_session_epoch(),
    })
    resp = RedirectResponse('/', 302)
    resp.set_cookie('renrenvpn_session', session, httponly=True, samesite='lax',
                    max_age=session_max_age(), secure=system_ops.is_secure(request))
    return resp


if __name__ == '__main__':
    from . import cli
    sys.exit(cli.main(sys.argv[1:]))
