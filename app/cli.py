"""Administrative CLI for recovery and maintenance independent of the web service.

    renrenvpn info | reset-password | reset-path | set-host | set-port
        | set-update-repo | update | repair | backup | restore | install | init-admin
"""

import argparse
import getpass
import hashlib
import http.client
import json
import os
import platform
import re
import secrets
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
from datetime import datetime
from pathlib import Path

from . import db, singbox, system_ops

BACKUP_DIR = db.DATA_ROOT / 'backup'
MAX_BACKUP_MEMBER = 64 * 1024 * 1024
# sing-box 1.14 with our build tags is ~70 MB unpacked; leave room for growth.
MAX_CORE_BINARY = 128 * 1024 * 1024
RESTORE_NAMES = ('panel.db', 'settings.json', 'cert.pem', 'key.pem')
# sing-box runs unprivileged and reads its certificate through the singbox/ group.
RESTORE_MODES = {'cert.pem': 0o640, 'key.pem': 0o640}
LOGIN_PATH_RE = re.compile(r'^[A-Za-z0-9_-]{8,128}$')
REPO_RE = re.compile(
    r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$')
APP_TAG_RE = re.compile(r'^(?:vpn-)?v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$')
SHA256_RE = re.compile(r'^[0-9a-f]{64}$')
ASSET_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$')
UPDATE_MANIFEST = 'renrenvpn-update.json'
UPDATE_SIGNATURE = UPDATE_MANIFEST + '.sig'
RELEASE_PUBLIC_KEY = Path(__file__).with_name('release-public-key.pem')
DEFAULT_UPDATE_REPO = 'iwantruncom/renrenVPN'
LEGACY_UPDATE_REPO = 'iwantruncom/iwantrun.com-VPN-Web-Manager'


def _update_repo():
    repo = db.get_setting('update_repo').strip()
    return DEFAULT_UPDATE_REPO if repo in ('', LEGACY_UPDATE_REPO) else repo


def _random_secret(length=18):
    """Generate a readable alphanumeric credential."""
    alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789'
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def _panel_base():
    return f'https://{system_ops.authority(singbox.public_host(), system_ops.panel_port())}'


def cmd_info(args):
    db.init_db()
    settings = db.all_settings()
    clients = db.list_clients()
    print('访问地址：' + f'{_panel_base()}/{system_ops.login_path()}')
    print('管理账号：' + (db.admin_username() or '(还没有创建)'))
    print('管理密码：不在这里显示。忘了就运行：renrenvpn reset-password')
    print('服务器地址：' + (settings.get('public_host') or '(未设置)'))
    print('用户：共 %d 个，其中 %d 个可用' % (len(clients), sum(1 for c in clients if c['enabled'])))
    print('已启用连接：' + ', '.join(
        singbox.BY_KEY[k].tech_name for k in singbox.enabled_keys(settings)))
    print('需要在云厂商安全组放行：' + ', '.join(
        singbox.firewall_rules(settings)
        + ['80/TCP（Let\'s Encrypt 证书自动续期）',
           f'{system_ops.panel_port()}/TCP（管理页面和订阅）']))
    print('sing-box 状态：' + ('运行中' if singbox.service_running() else '未运行'))
    print('更新仓库：' + _update_repo())
    print('当前发布：' + (settings.get('installed_release') or '(未知)'))
    return 0


def cmd_reset_password(args):
    db.init_db()
    username = db.admin_username() or 'admin'
    password = args.password or _random_secret()
    try:
        db.create_admin(username, password)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    db.bump_session_epoch()          # 吊销全部已签发的会话
    print(f'管理账号：{username}')
    print(f'管理密码：{password}')
    print('已退出所有旧的登录。')
    return 0


def cmd_reset_path(args):
    path = (args.path or ('login-' + secrets.token_hex(16))).strip().strip('/')
    if not LOGIN_PATH_RE.fullmatch(path):
        print('访问路径只能包含英文、数字、下划线和短横线，长度 8 到 128。', file=sys.stderr)
        return 2
    system_ops.save_web_settings({'login_path': path})
    print('新的访问地址：' + f'{_panel_base()}/{system_ops.login_path()}')
    print('旧地址立即失效，不需要重启。')
    return 0


def cmd_set_host(args):
    db.init_db()
    try:
        host = system_ops.canonical_public_ipv4(args.host)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    with singbox.config_lock():
        old = db.get_setting('public_host') or ''
        db.set_setting('public_host', host)
        try:
            result = _rebuild()
            if result:
                raise RuntimeError('新地址的连接配置没有生效')
        except Exception as exc:
            db.set_setting('public_host', old)
            try:
                singbox.apply()
            except Exception:
                pass
            print(f'服务器地址没有修改，已恢复原值：{exc}', file=sys.stderr)
            return 1
    print(f'服务器地址已设为：{host}')
    print('请立即重跑安装器，为新 IP 签发面板证书；完成前不要重启面板服务。')
    print('所有用户的连接信息都变了，安装完成后请重新发给他们。')
    return 0


def cmd_set_port(args):
    try:
        port = int(args.port)
    except (TypeError, ValueError):
        print('端口必须是 1 到 65535 之间的数字。', file=sys.stderr)
        return 2
    if not 1 <= port <= 65535:
        print('端口必须在 1 到 65535 之间。', file=sys.stderr)
        return 2
    if port == system_ops.ACME_PORT:
        print('80 端口留给证书续期，换一个。', file=sys.stderr)
        return 2
    old_port = system_ops.panel_port()
    if port == old_port:
        print(f'管理页面已经在使用 {port}。')
        return 0
    code, out, err = system_ops.run_cmd(
        ['ss', '-ltnH', f'sport = :{port}'], 5)
    if code == 0 and out.strip():
        print(f'{port} 端口已被其他程序占用。', file=sys.stderr)
        return 2
    system_ops.save_web_settings({'panel_port': port})
    try:
        code, out, err = system_ops.run_cmd(
            ['systemctl', 'restart', 'iwantrun-vpn-web'], 30)
        if code != 0:
            raise RuntimeError(err or out or '面板服务重启失败')
        code, out, err = system_ops.run_cmd(
            ['systemctl', 'is-active', '--quiet', 'iwantrun-vpn-web'], 10)
        if code != 0:
            raise RuntimeError(err or out or '面板服务没有进入运行状态')
        system_ops.open_port(port, 'tcp')
    except Exception as exc:
        system_ops.save_web_settings({'panel_port': old_port})
        system_ops.run_cmd(['systemctl', 'restart', 'iwantrun-vpn-web'], 30)
        print(f'端口修改失败，已恢复 {old_port}：{exc}', file=sys.stderr)
        return 1
    try:
        system_ops.close_port(old_port, 'tcp')
    except Exception as exc:
        print(f'提示：新端口已生效，但旧防火墙规则未能收回：{exc}', file=sys.stderr)
    print(f'管理页面端口已改为 {port}，服务已经重启。')
    print(f'别忘了在云厂商安全组放行 {port}/TCP。')
    return 0


def cmd_set_update_repo(args):
    repo = args.repo.strip()
    if not REPO_RE.fullmatch(repo):
        print('GitHub 仓库必须写成 owner/repo，例如 owner/renrenvpn。', file=sys.stderr)
        return 2
    db.init_db()
    db.set_setting('update_repo', repo)
    print(f'更新仓库已设为：https://github.com/{repo}')
    return 0


def _download(url, target, max_bytes):
    request = urllib.request.Request(url, headers={
        'Accept': 'application/vnd.github+json',
        'User-Agent': 'renrenvpn-updater',
        'X-GitHub-Api-Version': '2022-11-28',
    })
    digest = hashlib.sha256()
    total = 0
    with urllib.request.urlopen(request, timeout=30) as response, target.open('wb') as output:
        length = response.headers.get('Content-Length')
        if length and int(length) > max_bytes:
            raise ValueError('GitHub 返回的文件超过允许大小')
        while chunk := response.read(1024 * 1024):
            total += len(chunk)
            if total > max_bytes:
                raise ValueError('GitHub 返回的文件超过允许大小')
            output.write(chunk)
            digest.update(chunk)
    return digest.hexdigest()


def _extract_core(archive, version, arch, target):
    """Copy only the sing-box binary out of a release tar.gz.

    Every member is validated first so a tampered archive is rejected outright
    rather than partially trusted; nothing is ever written by tarfile.extract.
    """
    wanted = f'sing-box-{version}-linux-{arch}/sing-box'
    found = None
    with tarfile.open(archive, 'r:gz') as tar:
        for member in tar.getmembers():
            parts = Path(member.name).parts
            if (member.name.startswith('/') or '..' in parts
                    or not (member.isfile() or member.isdir())):
                raise ValueError(f'sing-box 安装包含非法成员：{member.name}')
            if member.name == wanted:
                if not member.isfile() or member.size > MAX_CORE_BINARY or found:
                    raise ValueError('sing-box 安装包结构不正确')
                found = member
        if found is None:
            raise ValueError('sing-box 安装包里没有找到内核程序')
        source = tar.extractfile(found)
        with source, target.open('wb') as output:
            shutil.copyfileobj(source, output, length=1024 * 1024)
    digest = hashlib.sha256()
    with target.open('rb') as binary:
        while chunk := binary.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _target_arch():
    machine = platform.machine().lower()
    if machine in ('x86_64', 'amd64'):
        return 'amd64'
    if machine in ('aarch64', 'arm64'):
        return 'arm64'
    raise ValueError(f'暂不支持这个 CPU 架构：{machine}')


def _verify_release_signature(manifest, signature):
    """Verify with the public key bundled in the installed release."""
    if not RELEASE_PUBLIC_KEY.is_file():
        raise ValueError('本机缺少更新公钥，已拒绝执行更新')
    result = subprocess.run([
        'openssl', 'pkeyutl', '-verify', '-pubin', '-inkey', str(RELEASE_PUBLIC_KEY),
        '-rawin', '-in', str(manifest), '-sigfile', str(signature),
    ], capture_output=True, text=True)
    if result.returncode != 0:
        raise ValueError('Release 签名校验失败，已拒绝执行更新')


def _release_manifest(path, tag, arch):
    try:
        manifest = json.loads(path.read_text(encoding='utf-8'))
        singbox_data = manifest['singbox']
        values = {
            'installer_sha256': manifest['installer_sha256'],
            'source_asset': manifest['source_asset'],
            'source_sha256': manifest['source_sha256'],
            'core_version': singbox_data['version'],
            'core_sha256': singbox_data[f'{arch}_sha256'],
        }
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise ValueError('Release manifest 格式不正确') from exc
    if (manifest.get('schema') != 1 or manifest.get('tag') != tag
            or not ASSET_RE.fullmatch(str(values['source_asset']))
            or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', str(values['core_version']))
            or any(not SHA256_RE.fullmatch(str(values[key]).lower())
                   for key in ('installer_sha256', 'source_sha256', 'core_sha256'))):
        raise ValueError('Release manifest 内容不正确')
    return {key: value.lower() if key.endswith('sha256') else value
            for key, value in values.items()}


def _set_update_status(state, message):
    """Report update progress to the panel's update page (it cannot read the journal)."""
    db.set_setting('update_status', json.dumps(
        {'state': state, 'message': message, 'at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')},
        ensure_ascii=False))


def cmd_update(args):
    if os.geteuid() != 0:
        print('更新需要 root 权限，请运行：sudo renrenvpn update', file=sys.stderr)
        return 2
    db.init_db()
    _set_update_status('running', '正在下载并校验新版本…')
    repo = _update_repo()
    if not REPO_RE.fullmatch(repo):
        print('还没有设置更新仓库，请先运行：renrenvpn set-update-repo owner/repo', file=sys.stderr)
        _set_update_status('failed', '没有设置更新来源，请 SSH 运行 renrenvpn update 查看。')
        return 2

    try:
        with tempfile.TemporaryDirectory(prefix='renrenvpn-update-') as tmp_name:
            tmp = Path(tmp_name)
            releases_path = tmp / 'releases.json'
            _download(f'https://api.github.com/repos/{repo}/releases?per_page=100',
                      releases_path, 2 * 1024 * 1024)
            releases = json.loads(releases_path.read_text())
            if not isinstance(releases, list):
                raise ValueError('GitHub Release 返回格式不正确')
            release = next((item for item in releases
                            if isinstance(item, dict)
                            and not item.get('draft')
                            and not item.get('prerelease')
                            and APP_TAG_RE.fullmatch(str(item.get('tag_name', '')))), None)
            if not release:
                raise ValueError('没有找到 v1.2.3 或 vpn-v1.2.3 格式的正式 Release')
            tag = release['tag_name']
            if (db.get_setting('installed_release') == tag
                    and db.get_setting('update_repo').strip() == repo):
                print(f'已经是最新版本：{tag}')
                _set_update_status('latest', f'当前已是 {tag}，不需要更新。')
                return 0

            manifest_path = tmp / UPDATE_MANIFEST
            signature_path = tmp / UPDATE_SIGNATURE
            release_base = f'https://github.com/{repo}/releases/download/{tag}'
            _download(f'{release_base}/{UPDATE_MANIFEST}', manifest_path, 64 * 1024)
            _download(f'{release_base}/{UPDATE_SIGNATURE}', signature_path, 4096)
            _verify_release_signature(manifest_path, signature_path)
            arch = _target_arch()
            release_data = _release_manifest(manifest_path, tag, arch)
            installer = tmp / 'install-webui.sh'
            source = tmp / release_data['source_asset']
            core_version = release_data['core_version']
            # Same location install-webui.sh uses; the tar.gz digest is pinned by the signed manifest.
            core_asset = f'sing-box-{core_version}-linux-{arch}.tar.gz'
            core_archive = tmp / core_asset
            installer_digest = _download(f'{release_base}/install-webui.sh', installer, 2 * 1024 * 1024)
            source_digest = _download(f'{release_base}/{release_data["source_asset"]}',
                                      source, 64 * 1024 * 1024)
            core_digest = _download(
                f'https://github.com/{repo}/releases/download/singbox-v{core_version}/{core_asset}',
                core_archive, 64 * 1024 * 1024)
            if (installer_digest != release_data['installer_sha256']
                    or source_digest != release_data['source_sha256']
                    or core_digest != release_data['core_sha256']):
                raise ValueError('Release 资产摘要校验失败')
            core = tmp / f'sing-box-{core_version}-linux-{arch}'
            binary_digest = _extract_core(core_archive, core_version, arch, core)

            installer.chmod(0o700)
            core.chmod(0o700)
            env = os.environ.copy()
            for key in ('IVPN_ONLINE_INSTALL', 'IVPN_REPO_ZIP_URL', 'IVPN_SINGBOX_BIN_PATH',
                        'IVPN_SINGBOX_SHA256', 'IVPN_SINGBOX_SHA256_AMD64',
                        'IVPN_SINGBOX_SHA256_ARM64'):
                env.pop(key, None)
            env.update({
                'IVPN_REPO': repo,
                'IVPN_REPO_ZIP_PATH': str(source),
                'IVPN_REPO_ZIP_SHA256': source_digest,
                'IVPN_SINGBOX_BIN_PATH': str(core),
                'IVPN_SINGBOX_SHA256': binary_digest,
            })
            result = subprocess.run(['bash', str(installer)], env=env)
            if result.returncode != 0:
                print('更新失败，安装器已恢复原程序和数据。', file=sys.stderr)
                _set_update_status('failed', '更新没有成功，已自动恢复到原来的版本，现有连接不受影响。')
                return result.returncode or 1
    except (OSError, ValueError, tarfile.TarError, http.client.HTTPException) as exc:
        print(f'无法从 GitHub 安全更新：{exc}', file=sys.stderr)
        _set_update_status('failed', f'没能下载或校验新版本，什么都没有改动：{exc}')
        return 1

    db.set_settings({'update_repo': repo, 'installed_release': tag})
    print(f'更新完成：{tag}。原有账号、密码、用户、设置和证书均已保留。')
    _set_update_status('done', f'已更新到 {tag}。账号密码、用户和订阅链接都没有变。')
    return 0


def _rebuild(extra=''):
    try:
        singbox.apply()
    except singbox.ConfigError as exc:
        print('配置没通过 sing-box 校验，线上配置未改动：', file=sys.stderr)
        print(exc, file=sys.stderr)
        return 1
    except Exception as exc:
        print(f'生效失败：{exc}', file=sys.stderr)
        return 1
    print('配置已重建并重启。' + (' ' + extra if extra else ''))
    return 0


def cmd_repair(args):
    db.init_db()
    singbox.ensure_reality_keys()
    return _rebuild()


def cmd_backup(args):
    """Create a consistent SQLite backup, including uncheckpointed WAL data."""
    db.init_db()
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime('%Y%m%d-%H%M%S')
    target = Path(args.path) if args.path else BACKUP_DIR / f'renrenvpn-{stamp}.tar.gz'
    with tempfile.TemporaryDirectory() as tmp:
        snapshot = Path(tmp) / 'panel.db'
        source = db.connect()
        dest = sqlite3.connect(snapshot)
        with dest:
            source.backup(dest)
        dest.close()
        source.close()
        with tarfile.open(target, 'w:gz') as tar:
            tar.add(snapshot, arcname='panel.db')
            if system_ops.WEB_SETTINGS.exists():
                tar.add(system_ops.WEB_SETTINGS, arcname='settings.json')
            # Preserve the pinned TLS certificate across restores; REALITY keys are in panel.db.
            for path, name in ((singbox.CERT_PATH, 'cert.pem'),
                               (singbox.KEY_PATH, 'key.pem')):
                if path.exists():
                    tar.add(path, arcname=name)
    # Backups contain private keys.
    target.chmod(0o600)
    print(f'备份已写入：{target}')
    return 0


def cmd_restore(args):
    archive = Path(args.path)
    if not archive.exists():
        print(f'找不到备份文件：{archive}', file=sys.stderr)
        return 2
    live_epoch = db.get_session_epoch() if db.DB_PATH.exists() else 0
    live_host = db.get_setting('public_host') if db.DB_PATH.exists() else ''
    live_port = system_ops.panel_port() if system_ops.WEB_SETTINGS.exists() else None
    with tempfile.TemporaryDirectory() as tmp_name:
        stage = Path(tmp_name) / 'stage'
        rollback = Path(tmp_name) / 'rollback'
        stage.mkdir(mode=0o700)
        rollback.mkdir(mode=0o700)
        try:
            with tarfile.open(archive) as tar:
                members = tar.getmembers()
                names = {member.name for member in members}
                if 'panel.db' not in names:
                    print('这个备份里没有 panel.db，不像是本面板的备份。', file=sys.stderr)
                    return 2
                if len(members) > len(RESTORE_NAMES) or names - set(RESTORE_NAMES):
                    raise ValueError('备份包含未知文件')
                for name in RESTORE_NAMES:
                    if name not in names:
                        continue
                    member = tar.getmember(name)
                    if not member.isfile() or member.size > MAX_BACKUP_MEMBER:
                        raise ValueError(f'非法备份成员：{name}')
                    source = tar.extractfile(member)
                    if source is None:
                        raise ValueError(f'无法读取备份成员：{name}')
                    target = stage / name
                    with source, target.open('wb') as output:
                        shutil.copyfileobj(source, output, length=1024 * 1024)
                    target.chmod(0o600)

            _validate_restore_stage(stage, live_epoch)
            moved_from = _pin_restore_to_this_server(stage, live_host, live_port)
        except (OSError, ValueError, tarfile.TarError, sqlite3.DatabaseError) as exc:
            print(f'备份校验失败：{exc}', file=sys.stderr)
            return 2

        targets = {
            'panel.db': db.DB_PATH,
            'settings.json': system_ops.WEB_SETTINGS,
            'cert.pem': singbox.CERT_PATH,
            'key.pem': singbox.KEY_PATH,
        }
        # Stop panel writes first, so the rollback snapshot is the latest state.
        active = system_ops.run_cmd(
            ['systemctl', 'is-active', 'iwantrun-vpn-web'], 5
        )[0] == 0
        if active:
            code, out, err = system_ops.run_cmd(
                ['systemctl', 'stop', 'iwantrun-vpn-web'], 30)
            if code != 0:
                print(f'无法暂停面板写入：{err or out}', file=sys.stderr)
                return 1

        existed = {}
        try:
            for name, target in targets.items():
                existed[name] = target.exists()
                if not target.exists():
                    continue
                if name == 'panel.db':
                    # A file copy misses commits still in the WAL; the backup API includes them.
                    live = sqlite3.connect(target)
                    snapshot = sqlite3.connect(rollback / name)
                    try:
                        live.backup(snapshot)
                    finally:
                        snapshot.close()
                        live.close()
                else:
                    shutil.copyfile(target, rollback / name)
        except (OSError, sqlite3.Error) as exc:
            print(f'无法为当前数据做回滚快照，什么都没有改动：{exc}', file=sys.stderr)
            if active:
                system_ops.run_cmd(['systemctl', 'start', 'iwantrun-vpn-web'], 30)
            return 1

        try:
            for name, target in targets.items():
                source = stage / name
                if not source.exists():
                    continue
                _atomic_copy(source, target, RESTORE_MODES.get(name, 0o600))
            for suffix in ('-wal', '-shm'):
                Path(str(db.DB_PATH) + suffix).unlink(missing_ok=True)
            result = _rebuild('如果管理页面端口变了，面板服务会在下面重新启动。')
            if result != 0:
                raise RuntimeError('恢复后的 sing-box 配置没有通过验证')
        except Exception as exc:
            for name, target in targets.items():
                old = rollback / name
                if old.exists():
                    _atomic_copy(old, target, RESTORE_MODES.get(name, 0o600))
                elif not existed[name]:
                    target.unlink(missing_ok=True)
            for suffix in ('-wal', '-shm'):
                Path(str(db.DB_PATH) + suffix).unlink(missing_ok=True)
            print(f'恢复失败，已还原原数据：{exc}', file=sys.stderr)
            if active:
                system_ops.run_cmd(['systemctl', 'start', 'iwantrun-vpn-web'], 30)
            return 1

        if active:
            code, out, err = system_ops.run_cmd(
                ['systemctl', 'start', 'iwantrun-vpn-web'], 30)
            if code == 0:
                # start returns at once for Type=simple; a bad restore crashes a moment later.
                time.sleep(3)
                code, out, err = system_ops.run_cmd(
                    ['systemctl', 'is-active', 'iwantrun-vpn-web'], 10)
            if code != 0:
                print(f'数据已恢复，但面板没有正常运行：{err or out}。'
                      '可运行 journalctl -u iwantrun-vpn-web 查看原因。', file=sys.stderr)
                return 1
    print('数据已恢复，所有旧的管理登录已失效。')
    if moved_from:
        print(f'备份来自 {moved_from}，已改用本机地址 {live_host}；用户刷新订阅后会自动更新，'
              '手动导入单条链接的用户需要重新获取。')
    return 0


def _pin_restore_to_this_server(stage, live_host, live_port):
    """Keep this server's public IP and panel port when restoring a backup.

    The panel certificate, its renewal and the firewall belong to this machine; a
    backup from another VPS (the usual reason to restore) must not point them elsewhere.
    Returns the backup's own address when it differed.
    """
    moved_from = ''
    if live_host:
        con = sqlite3.connect(stage / 'panel.db')
        try:
            row = con.execute("SELECT value FROM settings WHERE key='public_host'").fetchone()
            if row and row[0] and row[0] != live_host:
                moved_from = row[0]
            con.execute("INSERT INTO settings(key,value) VALUES ('public_host',?) "
                        "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (live_host,))
            con.commit()
        finally:
            con.close()
    settings_path = stage / 'settings.json'
    if live_port and settings_path.exists():
        settings = json.loads(settings_path.read_text())
        settings['panel_port'] = live_port
        settings_path.write_text(json.dumps(settings, ensure_ascii=False, indent=2))
    return moved_from


def _atomic_copy(source, target, mode):
    """Replace target atomically; when run as root, keep the directory owner's ownership."""
    system_ops.write_private_file(target, Path(source).read_bytes(), mode)


def _validate_restore_stage(stage, live_epoch):
    database = stage / 'panel.db'
    con = sqlite3.connect(database)
    try:
        if con.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
            raise ValueError('SQLite 完整性检查失败')
        tables = {row[0] for row in
                  con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        required = {'admins', 'settings', 'clients'}
        if not required <= tables:
            raise ValueError('数据库缺少必要的数据表')
        restored_row = con.execute(
            "SELECT value FROM settings WHERE key='session_epoch'"
        ).fetchone()
        restored_epoch = int(restored_row[0]) if restored_row else 0
        new_epoch = max(live_epoch, restored_epoch) + 1
        con.execute(
            "INSERT INTO settings(key,value) VALUES ('session_epoch',?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (str(new_epoch),),
        )
        con.commit()
    finally:
        con.close()

    settings_path = stage / 'settings.json'
    if settings_path.exists():
        settings = json.loads(settings_path.read_text())
        port = int(settings.get('panel_port', 0))
        path = str(settings.get('login_path', ''))
        if not 1 <= port <= 65535 or port == system_ops.ACME_PORT:
            raise ValueError('settings.json 的面板端口无效')
        if not LOGIN_PATH_RE.fullmatch(path):
            raise ValueError('settings.json 的登录路径无效')

    cert = stage / 'cert.pem'
    key = stage / 'key.pem'
    if cert.exists() != key.exists():
        raise ValueError('证书和私钥必须同时存在')
    if cert.exists():
        cert_code, cert_public, cert_err = system_ops.run_cmd(
            ['openssl', 'x509', '-in', str(cert), '-pubkey', '-noout'], 10)
        key_code, key_public, key_err = system_ops.run_cmd(
            ['openssl', 'pkey', '-in', str(key), '-pubout'], 10)
        if (cert_code != 0 or key_code != 0 or
                cert_public.strip() != key_public.strip()):
            raise ValueError(cert_err or key_err or '证书和私钥不匹配')


def cmd_init_admin(args):
    # Password comes from stdin, never argv: argv is world-readable in /proc while installing.
    if sys.stdin.isatty():
        password = getpass.getpass('管理密码：')
    else:
        password = sys.stdin.readline().removesuffix('\n')
    try:
        db.create_admin(args.username, password)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print('admin initialized')
    return 0


def cmd_install(args):
    """Initialize server identity, protocol credentials, certificate, and firewall rules."""
    db.init_db()
    if not db.get_setting('public_host'):
        host = detected = singbox.detect_public_ip()
        if detected:
            db.set_setting('public_host', detected)
        print('服务器地址：' + (host or '探测失败，请稍后用 renrenvpn set-host 手动设置'), flush=True)
    if not db.get_setting('reality_sni'):
        print('正在实测挑选伪装域名…', flush=True)
        sni = singbox.pick_sni()
        db.set_setting('reality_sni', sni)
        print(f'伪装域名：{sni}', flush=True)
    singbox.ensure_reality_keys()
    singbox.ensure_cert(singbox.public_host())
    singbox.sync_firewall()
    print('连接方式已准备好。', flush=True)
    # No enabled users means no inbound; adding the first user activates it.
    try:
        singbox.apply(restart=False)
    except singbox.ConfigError as exc:
        print(f'配置校验失败：{exc}', file=sys.stderr)
        return 1
    return 0


COMMANDS = {
    'info': (cmd_info, '显示访问地址、账号和需要放行的端口'),
    'reset-password': (cmd_reset_password, '重置管理密码并打印出来'),
    'reset-path': (cmd_reset_path, '换一个随机的管理页面地址'),
    'set-host': (cmd_set_host, '设置对外的服务器公网 IPv4'),
    'set-port': (cmd_set_port, '修改管理页面端口'),
    'set-update-repo': (cmd_set_update_repo, '设置用于更新的 GitHub 仓库'),
    'update': (cmd_update, '从已设置仓库的最新正式 Release 更新'),
    'repair': (cmd_repair, '按数据库重建 sing-box 配置并重启'),
    'backup': (cmd_backup, '备份数据库和面板设置'),
    'restore': (cmd_restore, '从备份恢复'),
    'install': (cmd_install, '安装阶段的一次性准备'),
    'init-admin': (cmd_init_admin, '创建或重置管理员（安装脚本用）'),
}


def main(argv=None):
    parser = argparse.ArgumentParser(prog='renrenvpn', description='人人VPN 面板管理命令')
    subparsers = parser.add_subparsers(dest='command', required=True)
    for name, (_handler, help_text) in COMMANDS.items():
        sub = subparsers.add_parser(name, help=help_text)
        if name == 'reset-password':
            sub.add_argument('password', nargs='?', default='', help='留空则随机生成')
        elif name == 'reset-path':
            sub.add_argument('path', nargs='?', default='', help='留空则随机生成')
        elif name == 'set-host':
            sub.add_argument('host')
        elif name == 'set-port':
            sub.add_argument('port')
        elif name == 'set-update-repo':
            sub.add_argument('repo')
        elif name == 'backup':
            sub.add_argument('path', nargs='?', default='', help='留空则写入默认备份目录')
        elif name == 'restore':
            sub.add_argument('path')
        elif name == 'init-admin':
            sub.add_argument('username')
    args = parser.parse_args(argv)
    return COMMANDS[args.command][0](args)


if __name__ == '__main__':
    sys.exit(main())
