"""Administrative account, server, protocol, and REALITY SNI settings."""

import json
import re
from datetime import datetime

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse

from .. import db, singbox, system_ops
from ..db import log_action, verify_admin
from ..web import (LOGIN_VERIFY_SLOTS, apply_config, csrf_token, login_blocked, login_url,
                   notices, preview_mode, record_login, redirect_with_message,
                   require_user, templates, verify_csrf)

router = APIRouter()

USERNAME_RE = re.compile(r'^[A-Za-z0-9_]{1,32}$')


def _update_status():
    # Written by `renrenvpn update` running as root in iwantrun-vpn-update.service.
    try:
        status = json.loads(db.get_setting('update_status') or '{}')
    except ValueError:
        return {}
    return status if isinstance(status, dict) else {}


@router.get('/settings')
def settings_page(request: Request, user: str = Depends(require_user)):
    settings = db.all_settings()
    return templates.TemplateResponse('settings.html', {
        'request': request,
        'active': 'settings',
        'csrf_token': csrf_token(request),
        'admin_username': user,
        'settings': settings,
        'enabled_keys': singbox.enabled_keys(settings),
        'all_protocols': singbox.PROTOCOLS,
        # The current request origin is the address the admin should bookmark.
        'login_full_url': str(request.base_url) + system_ops.login_path(),
        'panel_port': system_ops.panel_port(),
        'acme_port': system_ops.ACME_PORT,
        'firewall_rules': singbox.firewall_rules(settings),
        'update_status': _update_status(),
        **notices(request),
    })


@router.post('/settings/update')
def start_update(request: Request, user: str = Depends(require_user),
                 _: None = Depends(verify_csrf)):
    """Hand the update to a root oneshot unit; it restarts this panel midway."""
    if preview_mode():
        return redirect_with_message('/settings', msg='预览模式不会实际更新。')
    db.set_setting('update_status', json.dumps({
        'state': 'queued', 'message': '正在启动更新…',
        'at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
    }, ensure_ascii=False))
    try:
        system_ops.privileged_action({'action': 'start_update'})
    except Exception as exc:
        db.set_setting('update_status', '')
        log_action('start update', 'panel', 'error', str(exc))
        return redirect_with_message('/settings', error=f'没能启动更新：{exc}')
    log_action('start update', 'panel')
    return templates.TemplateResponse('update.html', {
        'request': request,
        'active': 'settings',
        'csrf_token': csrf_token(request),
    })


@router.get('/settings/update-status')
def update_status(user: str = Depends(require_user)):
    return _update_status()


@router.post('/settings/account')
def change_account(request: Request, user: str = Depends(require_user), _: None = Depends(verify_csrf),
                   current_password: str = Form(...), username: str = Form(...),
                   password: str = Form('')):
    username = username.strip()
    # Share the login throttle so a stolen session cannot brute-force the current password.
    ip = request.client.host if request.client else ''
    if login_blocked(ip, user):
        return redirect_with_message('/settings', error='失败次数太多，请 10 分钟后再试。')
    if not LOGIN_VERIFY_SLOTS.acquire(blocking=False):
        return redirect_with_message('/settings', error='请求较多，请稍后重试。')
    try:
        ok = verify_admin(user, current_password)
        record_login(user, ip, ok)
    finally:
        LOGIN_VERIFY_SLOTS.release()
    if not ok:
        log_action('change account', user, 'error', 'wrong current password')
        return redirect_with_message('/settings', error='当前密码不正确，请重新输入。')
    if not USERNAME_RE.match(username):
        return redirect_with_message('/settings', error='管理账号只能用英文、数字和下划线。')
    if password:
        try:
            db.validate_admin_password(password)
        except ValueError as exc:
            return redirect_with_message('/settings', error=str(exc))
    try:
        db.update_admin_credentials(user, username, password)
    except Exception:
        return redirect_with_message('/settings', error='这个管理账号不能用，换一个。')
    db.bump_session_epoch()
    log_action('change account', username)
    resp = RedirectResponse(login_url(), 302)
    resp.delete_cookie('renrenvpn_session')
    return resp


@router.post('/settings/server')
def change_server(request: Request, user: str = Depends(require_user), _: None = Depends(verify_csrf),
                  public_host: str = Form(''), session_days: str = Form('30'),
                  hy2_obfs: str = Form(''), protocols: list[str] = Form(default=[]),
                  reality_sni: str = Form(''), panel_port: str = Form('')):
    """Rebuild sing-box only when a setting changes its configuration."""
    try:
        host = system_ops.canonical_public_ipv4(public_host)
    except ValueError:
        return redirect_with_message('/settings', error='服务器地址格式不正确。')
    try:
        days = max(1, min(365, int(session_days)))
    except ValueError:
        days = 30
    try:
        requested_port = int(panel_port or system_ops.panel_port())
    except (TypeError, ValueError):
        return redirect_with_message('/settings', error='管理页面端口必须是数字。')
    if not 1024 <= requested_port <= 65535 or requested_port == system_ops.ACME_PORT:
        return redirect_with_message('/settings', error='管理页面端口必须在 1024 到 65535 之间。')
    old_port = system_ops.panel_port()
    port_changed = requested_port != old_port
    keys = [k for k in protocols if k in singbox.BY_KEY] or list(singbox.DEFAULT_KEYS)
    sni = reality_sni.strip()
    if sni and not re.match(r'^[A-Za-z0-9.\-]{1,253}$', sni):
        return redirect_with_message('/settings', error='伪装域名格式不正确。')

    with singbox.config_lock():
        before = db.all_settings()
        if (not preview_mode() and before.get('public_host')
                and host != before.get('public_host')):
            return redirect_with_message(
                '/settings',
                error='更换公网 IP 还需要重新签发面板证书。请先 SSH 运行 renrenvpn set-host，'
                      '再立即重跑安装器；网页中不会只改一半。')
        updates = {
            'public_host': host,
            'session_days': days,
            'hy2_obfs': hy2_obfs.strip(),
            'protocols': ','.join(keys),
        }
        if sni:
            updates['reality_sni'] = sni
            updates['reality_sni_ok'] = ('1' if preview_mode() else
                                         ('1' if singbox.sni_usable(sni) else '0'))
        db.set_settings(updates)
        after = db.all_settings()

        config_changed = any(before.get(k) != after.get(k) for k in db.CONFIG_KEYS)
        if config_changed:
            try:
                if not preview_mode():
                    singbox.sync_firewall(after, close_disabled=False)
                apply_config()
                if not preview_mode():
                    singbox.sync_firewall(after)
            except Exception as exc:
                db.set_settings({key: before.get(key, '') for key in updates})
                restored = True
                try:
                    # apply_config may already have switched sing-box to the new settings.
                    apply_config()
                except Exception:
                    restored = False
                if not preview_mode():
                    try:
                        singbox.sync_firewall(before)
                    except Exception:
                        restored = False
                log_action('change server', 'settings', 'error', str(exc))
                if not restored:
                    return redirect_with_message(
                        '/settings', error='设置没有生效，恢复原配置时也出错了。'
                                           '请在首页点一次「检查并修复」。')
                return redirect_with_message('/settings', error='设置没有生效，已恢复原来的配置。')

    if port_changed:
        if preview_mode():
            return redirect_with_message('/settings', msg='预览模式不会实际切换管理端口。')
        try:
            system_ops.privileged_action({
                'action': 'change_panel_port', 'port': requested_port,
            })
        except Exception as exc:
            log_action('change panel port', str(requested_port), 'error', str(exc))
            return redirect_with_message('/settings', error=f'其它设置已保存，但端口没有修改：{exc}')
        host = singbox.public_host()
        new_url = f'https://{system_ops.authority(host, requested_port)}/settings'
        log_action('change panel port', f'{old_port} -> {requested_port}')
        return templates.TemplateResponse('port-switch.html', {
            'request': request,
            'active': 'settings',
            'csrf_token': csrf_token(request),
            'new_port': requested_port,
            'old_port': old_port,
            'new_url': new_url,
        })
    log_action('change server', 'settings')
    message = ('设置已保存，所有连接信息已更新，请重新发给用户。'
               if config_changed else '设置已保存。')
    return redirect_with_message('/settings', msg=message)


@router.post('/settings/rescan-sni')
def rescan_sni(request: Request, user: str = Depends(require_user),
               _: None = Depends(verify_csrf), next: str = Form('/settings')):
    """Replace the REALITY target with a different reachable candidate.

    Existing standalone links contain the old SNI and must be redistributed.
    Subscription clients receive the change on their next refresh.
    """
    target = '/settings' if next != 'home' else '/'
    if preview_mode():
        return redirect_with_message(target, msg='预览模式不执行扫描。')
    try:
        with singbox.config_lock():
            before = db.all_settings()
            current = before.get('reality_sni', '')
            candidates = tuple(host for host in singbox.SNI_CANDIDATES if host != current)
            if not candidates:
                return redirect_with_message(
                    target, error='没有找到其他可用的伪装域名，原设置保持不变。')
            try:
                sni = singbox.pick_sni(candidates)
            except RuntimeError as exc:
                log_action('rescan sni', 'settings', 'error', str(exc))
                return redirect_with_message(
                    target, error='没有找到其他可用的伪装域名，原设置保持不变。')
            if sni == current:
                raise RuntimeError('扫描结果与当前伪装域名相同')
            if not singbox.sni_usable(sni):
                raise RuntimeError('挑选到的伪装域名复检失败')
            db.set_settings({'reality_sni': sni, 'reality_sni_ok': '1'})
            try:
                apply_config()
            except Exception:
                db.set_settings({
                    'reality_sni': before.get('reality_sni', ''),
                    'reality_sni_ok': before.get('reality_sni_ok', '0'),
                })
                raise
    except Exception as exc:
        log_action('rescan sni', 'settings', 'error', str(exc))
        return redirect_with_message(target, error='扫描失败，原来的伪装域名没有改变。')
    log_action('rescan sni', 'settings', 'ok', sni)
    return redirect_with_message(
        target, msg=(f'伪装域名已更换为 {sni}。订阅链接地址不变，客户端刷新后生效；'
                     '手动导入单条链接的用户需要重新获取连接。'))
