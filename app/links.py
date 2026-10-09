"""Generate protocol URIs, subscription payloads, and client import links."""

import base64
import hashlib
import re
from typing import NamedTuple
from urllib.parse import quote, urlencode

from . import db, singbox, system_ops
from .singbox import BY_KEY


def _hostport(host, port):
    # Bracket IPv6 literals before appending the port.
    return system_ops.authority(host, port)


def _remark(protocol, client_name):
    return f'{protocol.simple_name}-{client_name}'


def _build(scheme, userinfo, host, port, params, remark, path=''):
    """Build a deterministic URI with percent-encoded query and fragment fields."""
    query = urlencode(sorted((k, v) for k, v in params.items() if v), safe='', quote_via=quote)
    link = f'{scheme}://{userinfo}@{_hostport(host, port)}{path}'
    if query:
        link += '?' + query
    return f'{link}#{quote(remark, safe="")}'


def _spider_x(settings, client):
    """Derive a stable, client-specific REALITY spiderX path."""
    seed = f"{settings.get('reality_public_key', '')}|{client['sub_token']}"
    return '/' + hashlib.sha256(seed.encode()).hexdigest()[:15]


def share_link(key, client, settings, pin=''):
    protocol = BY_KEY[key]
    host = singbox.public_host(settings)
    port = protocol.port
    remark = _remark(protocol, client['name'])
    sni = settings.get('reality_sni') or singbox.FALLBACK_SNI

    if key == 'vless-reality':
        params = {
            'encryption': 'none',
            'security': 'reality',
            'sni': sni,
            'fp': 'chrome',
            'pbk': settings.get('reality_public_key', ''),
            'sid': settings.get('reality_short_id', ''),
            'spx': _spider_x(settings, client),
        }
        params.update({'type': 'tcp', 'flow': 'xtls-rprx-vision'})
        return _build('vless', client['uuid'], host, port, params, remark)

    if key == 'hysteria2':
        # Clients supporting pinSHA256 still validate the self-signed certificate.
        params = {'sni': host, 'insecure': '1', 'pinSHA256': pin}
        if settings.get('hy2_obfs'):
            params.update({'obfs': 'salamander', 'obfs-password': settings['hy2_obfs']})
        return _build('hysteria2', quote(client['password'], safe=''), host, port, params, remark)

    if key == 'anytls':
        params = {'sni': host, 'insecure': '1'}
        return _build('anytls', quote(client['password'], safe=''), host, port, params, remark, path='/')

    if key == 'tuic':
        # TUIC and Hysteria2 use distinct parameter names for TLS verification.
        params = {'congestion_control': 'bbr', 'udp_relay_mode': 'native',
                  'alpn': 'h3', 'allow_insecure': '1'}
        userinfo = f"{client['uuid']}:{quote(client['password'], safe='')}"
        return _build('tuic', userinfo, host, port, params, remark)

    raise RuntimeError(f'未知协议：{key}')


def client_links(client, settings=None, pin=None):
    settings = settings if settings is not None else db.all_settings()
    pin = singbox.cert_pin() if pin is None else pin
    # Generic URIs cannot reliably express public-key pins; expose pinned protocols via sing-box JSON.
    safe_raw = {'vless-reality'}
    return [(BY_KEY[key], share_link(key, client, settings, pin))
            for key in singbox.enabled_keys(settings) if key in safe_raw]


def subscription_body(client, settings=None, pin=None):
    """Encode newline-terminated links with padded standard Base64."""
    links = [link for _protocol, link in client_links(client, settings, pin)]
    body = ''.join(link + '\n' for link in links)
    return base64.b64encode(body.encode('utf-8')).decode('ascii')


def connection_card_links(client, settings, pin, preview=False):
    """Keep explicit single-node links separate from generic subscription payloads."""
    rows = []
    for key in singbox.enabled_keys(settings):
        supported = key == 'vless-reality' or (key == 'hysteria2' and (pin or preview))
        rows.append((BY_KEY[key], share_link(key, client, settings, pin) if supported else ''))
    return rows


def profile_title_header(client):
    """Encode non-ASCII profile titles for HTTP response headers."""
    title = f"人人VPN · {client['name']}"
    return 'base64:' + base64.b64encode(title.encode('utf-8')).decode('ascii')


def _self_signed_tls(server_name, key_pin, alpn=None):
    """Build TLS settings for protocols using the self-signed server certificate.

    A public-key pin provides certificate validation when available. Preview
    profiles without a certificate fall back to ``insecure``.
    """
    tls = {'enabled': True, 'server_name': server_name}
    if key_pin:
        tls['certificate_public_key_sha256'] = [key_pin]
    else:
        tls['insecure'] = True
    if alpn:
        tls['alpn'] = alpn
    return tls


def _client_outbound(key, client, settings, key_pin):
    """Build the client outbound for a configured server protocol."""
    protocol = BY_KEY[key]
    host = singbox.public_host(settings)
    sni = settings.get('reality_sni') or singbox.FALLBACK_SNI
    tag = protocol.simple_name

    if key == 'vless-reality':
        ob = {'type': 'vless', 'tag': tag, 'server': host, 'server_port': protocol.port,
              'uuid': client['uuid'],
              'tls': {'enabled': True, 'server_name': sni,
                      'utls': {'enabled': True, 'fingerprint': 'chrome'},
                      'reality': {'enabled': True,
                                  'public_key': settings.get('reality_public_key', ''),
                                  'short_id': settings.get('reality_short_id', '')}}}
        ob['flow'] = 'xtls-rprx-vision'
        return ob
    if key == 'hysteria2':
        ob = {'type': 'hysteria2', 'tag': tag, 'server': host, 'server_port': protocol.port,
              'password': client['password'],
              'tls': _self_signed_tls(host, key_pin, ['h3'])}
        if settings.get('hy2_obfs'):
            ob['obfs'] = {'type': 'salamander', 'password': settings['hy2_obfs']}
        return ob
    if key == 'anytls':
        return {'type': 'anytls', 'tag': tag, 'server': host, 'server_port': protocol.port,
                'password': client['password'],
                'tls': _self_signed_tls(host, key_pin)}
    if key == 'tuic':
        return {'type': 'tuic', 'tag': tag, 'server': host, 'server_port': protocol.port,
                'uuid': client['uuid'], 'password': client['password'],
                'congestion_control': 'bbr', 'zero_rtt_handshake': False,
                'tls': _self_signed_tls(host, key_pin, ['h3'])}
    raise RuntimeError(f'未知协议：{key}')


def singbox_profile(client, settings=None, key_pin=None):
    """Generate a client profile with IPv6 rejection before protocol sniffing.

    DNS strategy alone cannot block cached or externally resolved IPv6 targets.
    """
    settings = settings if settings is not None else db.all_settings()
    # This is the public-key pin, not the certificate fingerprint used in share links.
    key_pin = singbox.cert_public_key_pin() if key_pin is None else key_pin
    keys = singbox.enabled_keys(settings)
    proxies = [_client_outbound(key, client, settings, key_pin) for key in keys]
    names = [ob['tag'] for ob in proxies]

    return {
        'log': {'level': 'warn', 'timestamp': True},
        'dns': {
            'servers': [
                {'type': 'udp', 'tag': 'remote', 'server': '8.8.8.8', 'detour': '自动选择'},
                {'type': 'local', 'tag': 'local'},
            ],
            'rules': [{'clash_mode': 'Direct', 'server': 'local'}],
            'final': 'remote',
            # Query A records only as the first IPv6 safeguard.
            'strategy': 'ipv4_only',
        },
        'inbounds': [{
            'type': 'tun', 'tag': 'tun-in',
            # Capture IPv6 in the tunnel before rejecting it in routing.
            'address': ['172.19.0.1/30', 'fdfe:dcba:9876::1/126'],
            'auto_route': True, 'strict_route': True, 'stack': 'mixed',
            'mtu': 1400,
        }],
        'outbounds': [
            {'type': 'selector', 'tag': '手动选择',
             'outbounds': ['自动选择'] + names, 'default': '自动选择'},
            {'type': 'urltest', 'tag': '自动选择', 'outbounds': names,
             'url': 'https://www.gstatic.com/generate_204', 'interval': '3m'},
            *proxies,
            {'type': 'direct', 'tag': 'direct'},
        ],
        'route': {
            'default_domain_resolver': {'server': 'local', 'strategy': 'ipv4_only'},
            'rules': [
                # Keep this rule before sniff; no_drop preserves immediate IPv4 fallback.
                # See docs/singbox-manual.md, section 2.3.
                {'ip_version': 6, 'action': 'reject', 'no_drop': True},
                {'action': 'sniff'},
                {'protocol': 'dns', 'action': 'hijack-dns'},
                {'ip_is_private': True, 'outbound': 'direct'},
            ],
            'final': '手动选择',
            'auto_detect_interface': True,
        },
    }


def deep_links(sub_url):
    """Generate import URIs using each client's expected scheme."""
    encoded = quote(sub_url, safe='')
    # sing-box clients need the full profile to apply the IPv6 route rule.
    profile = quote(sub_url.rstrip('/') + '/singbox.json', safe='')
    singbox = f'sing-box://import-remote-profile?url={profile}'
    karing = f'karing://install-config?url={encoded}&name={quote("人人VPN", safe="")}'
    return {
        'singbox-ios': singbox,
        'singbox-mac': singbox,
        'singbox-windows': singbox,
        'karing-ios': karing,
        'karing-android': karing,
    }


class App(NamedTuple):
    name: str
    key: str
    free: bool
    where: str      # 安装来源说明


class Platform(NamedTuple):
    key: str
    label: str
    apps: tuple
    blocked: bool   # 该平台应用商店的国区是否无法获取客户端


class DownloadOption(NamedTuple):
    label: str
    url: str


PLATFORMS = (
    Platform('ios', 'iPhone / iPad', (
        App('sing-box MT', 'singbox-ios', True, '在 App Store 安装官方客户端'),
        App('Karing', 'karing-ios', True, '在 App Store 安装'),
    ), blocked=True),
    Platform('android', 'Android 手机 / 平板', (
        App('Karing', 'karing-android', True, '推荐普通手机使用 64 位安装包'),
        App('v2rayNG', 'v2rayng-android', True, '推荐普通手机使用 64 位安装包'),
    ), blocked=False),
    Platform('windows', 'Windows 电脑', (
        App('sing-box', 'singbox-windows', True, '下载官方图形客户端安装程序'),
        App('v2rayN', 'v2rayn-windows', True, '下载压缩包，解压后运行 v2rayN.exe'),
    ), blocked=False),
    Platform('mac', 'Mac 电脑', (
        App('sing-box', 'singbox-mac', True, '通用安装包适用于 Apple 芯片和 Intel Mac'),
        App('v2rayN', 'v2rayn-mac', True, '按 Mac 的芯片类型选择安装包'),
    ), blocked=False),
)

DOWNLOADS = {
    'singbox-ios': (DownloadOption('前往 App Store',
                                   'https://apps.apple.com/us/app/sing-box-mt/id6785326793'),),
    'karing-ios': (DownloadOption('前往 App Store',
                                 'https://apps.apple.com/us/app/karing/id6472431552'),),
    'karing-android': (
        DownloadOption('下载 64 位版', '/download/karing-android-arm64'),
        DownloadOption('旧设备 32 位版', '/download/karing-android-armv7'),
    ),
    'v2rayng-android': (
        DownloadOption('下载 64 位版', '/download/v2rayng-android-arm64'),
        DownloadOption('旧设备 32 位版', '/download/v2rayng-android-armv7'),
    ),
    'singbox-windows': (
        DownloadOption('下载 x64 版', '/download/singbox-windows-x64'),
        DownloadOption('Windows ARM 版', '/download/singbox-windows-arm64'),
    ),
    'v2rayn-windows': (
        DownloadOption('下载 x64 版', '/download/v2rayn-windows-x64'),
        DownloadOption('Windows ARM 版', '/download/v2rayn-windows-arm64'),
    ),
    'singbox-mac': (DownloadOption('下载最新版', '/download/singbox-mac'),),
    'v2rayn-mac': (
        DownloadOption('Apple 芯片版', '/download/v2rayn-mac-arm64'),
        DownloadOption('Intel 芯片版', '/download/v2rayn-mac-x64'),
    ),
}


PLATFORM_HELP_URL = 'https://iwantrun.com/category/vpn-proxy'


# Anchor on known UA prefixes. A substring test for "sing-box" would also match Hiddify,
# which discards route rules and therefore must receive the Base64 list.
_SINGBOX_JSON_UA = re.compile(r'^(SFA|SFI|SFM|SFT|Karing)', re.I)


def wants_singbox_json(user_agent):
    """Return whether the client expects a complete sing-box JSON profile."""
    return bool(_SINGBOX_JSON_UA.match(user_agent or ''))


def detect_platform(user_agent):
    """Infer a platform from the user agent for initial guide selection."""
    ua = (user_agent or '').lower()
    if 'iphone' in ua or 'ipad' in ua or 'ipod' in ua:
        return 'ios'
    if 'android' in ua:
        return 'android'
    if 'mac os' in ua or 'macintosh' in ua:
        return 'mac'
    if 'windows' in ua:
        return 'windows'
    return ''
