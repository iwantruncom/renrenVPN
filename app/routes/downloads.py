"""Redirect client downloads to platform-specific assets in the latest stable release."""

import functools
import json
import re
import time
import urllib.request
from urllib.parse import quote

from fastapi import APIRouter, HTTPException
from fastapi.responses import RedirectResponse


router = APIRouter()

ASSETS = {
    'singbox-mac': ('SagerNet/sing-box', r'SFM-[0-9][\w.-]*-Universal\.pkg'),
    'singbox-windows-x64': ('SagerNet/sing-box', r'SFW-[0-9][\w.-]*-x64\.exe'),
    'singbox-windows-arm64': ('SagerNet/sing-box', r'SFW-[0-9][\w.-]*-arm64\.exe'),
    'v2rayn-mac-arm64': ('2dust/v2rayN', r'v2rayN-macos-arm64\.dmg'),
    'v2rayn-mac-x64': ('2dust/v2rayN', r'v2rayN-macos-64\.dmg'),
    'v2rayn-windows-x64': ('2dust/v2rayN', r'v2rayN-windows-64\.zip'),
    'v2rayn-windows-arm64': ('2dust/v2rayN', r'v2rayN-windows-arm64\.zip'),
    'karing-android-arm64': ('KaringX/karing', r'karing_[0-9.]+_android_arm64-v8a\.apk'),
    'karing-android-armv7': ('KaringX/karing', r'karing_[0-9.]+_android_armeabi-v7a\.apk'),
    'v2rayng-android-arm64': ('2dust/v2rayNG', r'v2rayNG_[0-9.]+_arm64-v8a\.apk'),
    'v2rayng-android-armv7': ('2dust/v2rayNG', r'v2rayNG_[0-9.]+_armeabi-v7a\.apk'),
}


@functools.lru_cache(maxsize=16)
def latest_release(repo, interval):
    """Fetch once per repo per hour; failures are cached too (lru_cache skips exceptions)."""
    request = urllib.request.Request(
        f'https://api.github.com/repos/{repo}/releases/latest',
        headers={'Accept': 'application/vnd.github+json',
                 'User-Agent': 'renrenvpn-panel'},
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return json.load(response)
    except (OSError, ValueError):
        # An empty release fails tag validation, so callers fall back to the releases page.
        return {}


def latest_asset_url(key):
    repo, pattern = ASSETS[key]
    release = latest_release(repo, int(time.time() // 3600))
    tag = release.get('tag_name', '')
    if not re.fullmatch(r'[A-Za-z0-9._-]+', tag):
        raise ValueError('Invalid release tag')
    matches = [asset['name'] for asset in release.get('assets', ())
               if asset.get('state') == 'uploaded'
               and re.fullmatch(pattern, asset.get('name', ''))]
    if len(matches) != 1:
        raise ValueError('Release asset missing or ambiguous')
    return (f'https://github.com/{repo}/releases/download/'
            f'{quote(tag, safe="")}/{quote(matches[0], safe="")}')


@router.get('/download/{key}')
def client_download(key: str):
    if key not in ASSETS:
        raise HTTPException(status_code=404)
    try:
        url = latest_asset_url(key)
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
        repo = ASSETS[key][0]
        url = f'https://github.com/{repo}/releases/latest'
    return RedirectResponse(url, status_code=302)
