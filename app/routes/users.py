"""Client lifecycle and subscription-token management routes."""

from urllib.parse import quote

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse

from .. import db, links, singbox
from ..db import CLIENT_NAME_RE, log_action
from ..web import (apply_config, client_rows, csrf_token, notices, redirect_with_message,
                   require_user, templates, verify_csrf)

router = APIRouter()


@router.get('/users')
def users_page(request: Request, user: str = Depends(require_user)):
    return templates.TemplateResponse('users.html', {
        'request': request,
        'active': 'users',
        'csrf_token': csrf_token(request),
        'clients': client_rows(request),
        'downloads': links.DOWNLOADS,
        **notices(request),
    })


@router.post('/users/add')
def users_add(request: Request, user: str = Depends(require_user), _: None = Depends(verify_csrf),
              name: str = Form(...), next: str = Form('')):
    # Return to the second guide step when the request came from the home-page flow.
    fail_to = '/?guide_error=1' if next == 'guide' else '/users'
    name = name.strip()
    if not CLIENT_NAME_RE.match(name):
        return redirect_with_message(fail_to, error='名称只能用英文、数字和下划线，最长 32 个字符。')
    with singbox.config_lock():
        if not db.add_client(name):
            return redirect_with_message(fail_to, error='这个名称已经用过了，换一个。')
        try:
            apply_config()
        except Exception as exc:
            db.delete_client(name)
            log_action('add client', name, 'error', str(exc))
            return redirect_with_message(fail_to, error='没有添加成功，请先在首页点一次「检查并修复」。')
    log_action('add client', name)
    if next == 'guide':
        return RedirectResponse(f'/?guide={quote(name)}', 302)
    return redirect_with_message(f'/users?open={quote(name)}',
                                 msg=f'{name} 已经添加。把下面的教程链接和访问码发给他就能用。')


@router.post('/users/{name}/toggle')
def users_toggle(request: Request, name: str, user: str = Depends(require_user),
                 _: None = Depends(verify_csrf)):
    # Read under the lock: a concurrent change must not be undone by a stale rollback.
    with singbox.config_lock():
        client = db.get_client(name)
        if not client:
            return redirect_with_message('/users', error='没有找到这个用户。')
        enable = not client['enabled']
        db.set_client_enabled(name, enable)
        try:
            apply_config()
        except Exception as exc:
            db.set_client_enabled(name, client['enabled'])
            log_action('toggle client', name, 'error', str(exc))
            return redirect_with_message('/users', error='暂时无法更改状态，请稍后再试。')
    return redirect_with_message('/users', msg=f'{name} 已经恢复使用。' if enable else f'{name} 已经暂停。')


@router.post('/users/{name}/delete')
def users_delete(request: Request, name: str, user: str = Depends(require_user),
                 _: None = Depends(verify_csrf)):
    with singbox.config_lock():
        client = db.get_client(name)
        if not client:
            return redirect_with_message('/users', error='没有找到这个用户。')
        traffic = db.all_traffic().get(name)
        db.delete_client(name)
        try:
            apply_config()
        except Exception as exc:
            db.restore_client(client, traffic)
            log_action('delete client', name, 'error', str(exc))
            return redirect_with_message('/users', error='没有删除成功，旧连接仍然有效。')
    log_action('delete client', name)
    return redirect_with_message('/users', msg=f'{name} 已经删除，他手上的链接立刻失效。')


@router.post('/users/{name}/rotate')
def users_rotate(request: Request, name: str, user: str = Depends(require_user),
                 _: None = Depends(verify_csrf)):
    """Rotate the subscription token and protocol credentials, invalidating old links."""
    if not db.get_client(name):
        return redirect_with_message('/users', error='没有找到这个用户。')
    with singbox.config_lock():
        rotated = db.rotate_client_credentials(name)
        if not rotated:
            return redirect_with_message('/users', error='没有找到这个用户。')
        old, _new = rotated
        try:
            apply_config()
        except Exception as exc:
            db.restore_client_credentials(name, old)
            log_action('rotate credentials', name, 'error', str(exc))
            return redirect_with_message('/users', error='没有换成功，旧链接和旧连接仍然有效。')
    log_action('rotate credentials', name)
    return redirect_with_message('/users', msg=f'{name} 的旧链接和旧连接已经全部失效，请重新发送。')


@router.post('/users/{name}/rotate-guide')
def users_rotate_guide(request: Request, name: str, user: str = Depends(require_user),
                       _: None = Depends(verify_csrf)):
    if not db.rotate_guide_token(name):
        return redirect_with_message('/users', error='没有找到这个用户。')
    log_action('rotate guide', name)
    return redirect_with_message('/users', msg=f'{name} 的旧教程入口和访问码已失效，VPN 连接不受影响。')
