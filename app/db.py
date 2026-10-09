"""Persist panel state used to derive sing-box configuration."""

import os
import re
import sqlite3
import secrets
import uuid
import bcrypt
from pathlib import Path
from datetime import datetime

# The data root defaults to /etc/freedom-vpn; IVPN_DATA_DIR supports isolated runs.
DATA_ROOT = Path(os.environ.get('IVPN_DATA_DIR', '/etc/freedom-vpn'))
DB_PATH = DATA_ROOT / 'web' / 'panel.db'
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

# Restrict database files and their parent directory because they contain credentials.
def _harden_perms():
    try:
        for d in (DATA_ROOT, DB_PATH.parent):
            if d.exists():
                os.chmod(d, 0o700)
        for f in DB_PATH.parent.glob('panel.db*'):   # Includes SQLite WAL and SHM files.
            os.chmod(f, 0o600)
    except OSError:
        pass                                          # Ownership may be managed externally.


_harden_perms()

CLIENT_NAME_RE = re.compile(r'^[A-Za-z0-9_]{1,32}$')
MIN_ADMIN_PASSWORD_BYTES = 8
MAX_ADMIN_PASSWORD_BYTES = 72

# Changes to these settings require rebuilding the sing-box configuration.
CONFIG_KEYS = {'public_host', 'protocols', 'hy2_obfs', 'reality_sni'}

DEFAULT_SETTINGS = {
    'public_host': '',                              # Populated from the detected public IP.
    'protocols': 'vless-reality,hysteria2',         # Default TCP and UDP inbounds on port 443.
    'hy2_obfs': '',                                 # Optional Salamander password.
    'reality_sni': '',                              # Populated during installation.
    'reality_private_key': '',
    'reality_public_key': '',
    'reality_short_id': '',
    'session_days': '30',
    'session_epoch': '0',
    'update_repo': '',                              # Authorized GitHub release source.
    'installed_release': '',                        # Last successfully installed release tag.
    # Health state for the current REALITY target; it does not affect generated config.
    'reality_sni_ok': '1',
}


def _now():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')


def connect():
    con = sqlite3.connect(DB_PATH, timeout=10)
    con.row_factory = sqlite3.Row
    # WAL and busy_timeout allow concurrent panel and CLI access.
    con.execute('PRAGMA journal_mode=WAL')
    con.execute('PRAGMA busy_timeout=5000')
    return con


def init_db():
    con = connect()
    con.executescript("""
    CREATE TABLE IF NOT EXISTS admins (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT);
    CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS clients (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE,
        uuid TEXT NOT NULL,
        password TEXT NOT NULL,
        sub_token TEXT NOT NULL UNIQUE,
        guide_token TEXT NOT NULL UNIQUE,
        enabled INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS operation_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        action TEXT NOT NULL, target TEXT, result TEXT, message TEXT,
        created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS login_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT, ip TEXT, success INTEGER, message TEXT,
        created_at TEXT NOT NULL);
    -- 累计流量。sing-box 的计数器在内存里，读一次就清零（reset=True），
    -- 面板把每次读到的增量累加到这里，所以重启内核不会把历史清掉。
    CREATE TABLE IF NOT EXISTS traffic (
        name TEXT PRIMARY KEY,
        uplink INTEGER NOT NULL DEFAULT 0,
        downlink INTEGER NOT NULL DEFAULT 0,
        last_seen TEXT);
    -- 登录限流每次请求都按 (ip, created_at) 数失败次数，没索引会随日志增长变慢。
    CREATE INDEX IF NOT EXISTS idx_login_logs_ip ON login_logs(ip, created_at);
    """)
    for key, value in DEFAULT_SETTINGS.items():
        con.execute('INSERT OR IGNORE INTO settings(key,value) VALUES (?,?)', (key, value))
    _migrate_guide_tokens(con)
    _migrate_legacy(con)
    con.commit()
    con.close()
    _harden_perms()      # Reapply permissions after SQLite creates the database.


def _migrate_legacy(con):
    """Migrate legacy per-protocol users to one client record per name.

    Legacy credentials are incompatible with the fixed-port configuration.
    The historical ``owner`` entry is not a client account.
    """
    tables = {row[0] for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if 'users' not in tables:
        return
    if not con.execute('SELECT COUNT(*) FROM clients').fetchone()[0]:
        names = [row[0] for row in con.execute('SELECT DISTINCT username FROM users ORDER BY id')]
        for name in names:
            if name != 'owner' and CLIENT_NAME_RE.match(name):
                _insert_client(con, name)
    con.execute('DROP TABLE users')
    if 'protocols' in tables:
        con.execute('DROP TABLE protocols')


def _migrate_guide_tokens(con):
    columns = {row['name'] for row in con.execute('PRAGMA table_info(clients)')}
    if 'guide_token' not in columns:
        con.execute('ALTER TABLE clients ADD COLUMN guide_token TEXT')
    for row in con.execute('SELECT id FROM clients WHERE guide_token IS NULL OR guide_token=""'):
        con.execute('UPDATE clients SET guide_token=? WHERE id=?', (new_sub_token(), row['id']))
    con.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_clients_guide_token ON clients(guide_token)')


# ---------------------------------------------------------------------------
# 设置
# ---------------------------------------------------------------------------
def get_setting(key, default=''):
    con = connect()
    row = con.execute('SELECT value FROM settings WHERE key=?', (key,)).fetchone()
    con.close()
    return row['value'] if row else default


def set_setting(key, value):
    con = connect()
    con.execute(
        'INSERT INTO settings(key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',
        (key, str(value)),
    )
    con.commit()
    con.close()


def set_settings(values):
    """在一个 SQLite 事务里更新一组互相关联的设置。"""
    con = connect()
    try:
        con.execute('BEGIN IMMEDIATE')
        con.executemany(
            'INSERT INTO settings(key,value) VALUES (?,?) '
            'ON CONFLICT(key) DO UPDATE SET value=excluded.value',
            [(key, str(value)) for key, value in values.items()],
        )
        con.commit()
    finally:
        con.close()


def all_settings():
    con = connect()
    rows = con.execute('SELECT key, value FROM settings').fetchall()
    con.close()
    return {**DEFAULT_SETTINGS, **{row['key']: row['value'] for row in rows}}


def get_session_epoch():
    return int(get_setting('session_epoch', '0') or 0)


def bump_session_epoch():
    """自增会话纪元，令所有已签发的登录立即失效（改密码时调用）。"""
    con = connect()
    try:
        con.execute('BEGIN IMMEDIATE')
        con.execute(
            "UPDATE settings SET value=CAST(value AS INTEGER)+1 WHERE key='session_epoch'"
        )
        value = int(con.execute(
            "SELECT value FROM settings WHERE key='session_epoch'"
        ).fetchone()[0])
        con.commit()
        return value
    finally:
        con.close()


# ---------------------------------------------------------------------------
# 用户
# ---------------------------------------------------------------------------
def _insert_client(con, name):
    con.execute(
        'INSERT INTO clients(name,uuid,password,sub_token,guide_token,enabled,created_at) '
        'VALUES (?,?,?,?,?,1,?)',
        (name, str(uuid.uuid4()), secrets.token_urlsafe(16), new_sub_token(),
         new_sub_token(), _now()),
    )


def new_sub_token():
    """Generate a 128-bit subscription bearer token."""
    return secrets.token_hex(16)


def list_clients():
    con = connect()
    rows = con.execute('SELECT * FROM clients ORDER BY id').fetchall()
    con.close()
    return [dict(row) for row in rows]


def get_client(name):
    con = connect()
    row = con.execute('SELECT * FROM clients WHERE name=?', (name,)).fetchone()
    con.close()
    return dict(row) if row else None


def get_client_by_token(token):
    con = connect()
    row = con.execute('SELECT * FROM clients WHERE sub_token=?', (token,)).fetchone()
    con.close()
    return dict(row) if row else None


def get_client_by_guide_token(token):
    con = connect()
    row = con.execute('SELECT * FROM clients WHERE guide_token=?', (token,)).fetchone()
    con.close()
    return dict(row) if row else None


def add_client(name):
    """Insert a client; return False when the name already exists.

    上层预检挡不住并发提交（如两个标签页同时提交），由唯一索引做最终裁决：
    无需额外加锁，也不会返回 500。
    """
    con = connect()
    try:
        _insert_client(con, name)
        con.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        con.close()


def set_client_enabled(name, enabled):
    con = connect()
    con.execute('UPDATE clients SET enabled=? WHERE name=?', (1 if enabled else 0, name))
    con.commit()
    con.close()


def delete_client(name):
    con = connect()
    con.execute('DELETE FROM clients WHERE name=?', (name,))
    con.execute('DELETE FROM traffic WHERE name=?', (name,))
    con.commit()
    con.close()


def restore_client(client, traffic=None):
    """配置应用失败时恢复刚删除的完整凭据，以及 delete_client 一并清掉的历史流量。"""
    con = connect()
    try:
        con.execute(
            'INSERT INTO clients(id,name,uuid,password,sub_token,guide_token,enabled,created_at) '
            'VALUES (?,?,?,?,?,?,?,?)',
            (client['id'], client['name'], client['uuid'], client['password'],
             client['sub_token'], client['guide_token'], client['enabled'], client['created_at']),
        )
        if traffic:
            con.execute('INSERT INTO traffic(name,uplink,downlink,last_seen) VALUES (?,?,?,?)',
                        (client['name'], traffic['uplink'], traffic['downlink'],
                         traffic.get('last_seen')))
        con.commit()
    finally:
        con.close()


# ---------------------------------------------------------------------------
# 流量
# ---------------------------------------------------------------------------
def add_traffic(deltas):
    """Accumulate traffic deltas and update activity only for nonzero samples."""
    rows = [(name, up, down) for name, (up, down) in deltas.items() if up or down]
    if not rows:
        return
    now = _now()
    con = connect()
    con.executemany(
        'INSERT INTO traffic(name,uplink,downlink,last_seen) VALUES (?,?,?,?) '
        'ON CONFLICT(name) DO UPDATE SET uplink=uplink+excluded.uplink, '
        'downlink=downlink+excluded.downlink, last_seen=excluded.last_seen',
        [(name, up, down, now) for name, up, down in rows],
    )
    con.commit()
    con.close()


def all_traffic():
    con = connect()
    rows = con.execute('SELECT * FROM traffic').fetchall()
    con.close()
    return {row['name']: dict(row) for row in rows}


def reset_traffic(name):
    con = connect()
    con.execute('DELETE FROM traffic WHERE name=?', (name,))
    con.commit()
    con.close()


def rotate_client_credentials(name):
    """原子轮换订阅 token 和所有协议凭据，返回 (旧值, 新值)。"""
    con = connect()
    try:
        con.execute('BEGIN IMMEDIATE')
        row = con.execute(
            'SELECT uuid,password,sub_token,guide_token FROM clients WHERE name=?', (name,)
        ).fetchone()
        if not row:
            con.rollback()
            return None
        old = dict(row)
        new = {
            'uuid': str(uuid.uuid4()),
            'password': secrets.token_urlsafe(24),
            'sub_token': new_sub_token(),
            'guide_token': new_sub_token(),
        }
        con.execute(
            'UPDATE clients SET uuid=?,password=?,sub_token=?,guide_token=? WHERE name=?',
            (new['uuid'], new['password'], new['sub_token'], new['guide_token'], name),
        )
        con.commit()
        return old, new
    finally:
        con.close()


def restore_client_credentials(name, values):
    con = connect()
    try:
        con.execute(
            'UPDATE clients SET uuid=?,password=?,sub_token=?,guide_token=? WHERE name=?',
            (values['uuid'], values['password'], values['sub_token'], values['guide_token'], name),
        )
        con.commit()
    finally:
        con.close()


def rotate_sub_token(name):
    """保留旧接口；语义为同时撤销已签发的协议凭据。"""
    rotated = rotate_client_credentials(name)
    return rotated[1]['sub_token'] if rotated else ''


def rotate_guide_token(name):
    token = new_sub_token()
    con = connect()
    try:
        cursor = con.execute('UPDATE clients SET guide_token=? WHERE name=?', (token, name))
        con.commit()
        return token if cursor.rowcount else ''
    finally:
        con.close()


# ---------------------------------------------------------------------------
# 管理员
# ---------------------------------------------------------------------------
def validate_admin_password(password):
    raw = str(password).encode('utf-8')
    if not MIN_ADMIN_PASSWORD_BYTES <= len(raw) <= MAX_ADMIN_PASSWORD_BYTES:
        raise ValueError('管理密码必须为 8 到 72 个 UTF-8 字节')
    return raw


def _hash_password(password):
    return bcrypt.hashpw(validate_admin_password(password), bcrypt.gensalt()).decode('ascii')


def _check_password(password, password_hash):
    try:
        # Truncate to bcrypt's 72-byte limit so legacy over-length passwords still verify and can be replaced.
        return bcrypt.checkpw(str(password).encode('utf-8')[:MAX_ADMIN_PASSWORD_BYTES],
                              password_hash.encode('ascii'))
    except (ValueError, TypeError):
        return False


def create_admin(username, password):
    """创建或重置唯一管理员，供安装脚本和恢复命令使用。"""
    password_hash = _hash_password(password)
    init_db()
    con = connect()
    now = _now()
    con.execute(
        'INSERT INTO admins (username,password_hash,created_at,updated_at) VALUES (?,?,?,?) '
        'ON CONFLICT(username) DO UPDATE SET password_hash=excluded.password_hash, updated_at=excluded.updated_at',
        (username, password_hash, now, now),
    )
    con.commit()
    con.close()


def admin_username():
    con = connect()
    row = con.execute('SELECT username FROM admins ORDER BY id LIMIT 1').fetchone()
    con.close()
    return row['username'] if row else ''


def has_admin():
    con = connect()
    row = con.execute('SELECT 1 FROM admins LIMIT 1').fetchone()
    con.close()
    return bool(row)


def update_admin_credentials(username, new_username, new_password=''):
    password_hash = _hash_password(new_password) if new_password else ''
    con = connect()
    if new_password:
        con.execute(
            'UPDATE admins SET username=?, password_hash=?, updated_at=? WHERE username=?',
            (new_username, password_hash, _now(), username),
        )
    else:
        con.execute(
            'UPDATE admins SET username=?, updated_at=? WHERE username=?',
            (new_username, _now(), username),
        )
    con.commit()
    con.close()


def verify_admin(username, password):
    con = connect()
    row = con.execute('SELECT password_hash FROM admins WHERE username=?', (username,)).fetchone()
    con.close()
    return bool(row and _check_password(password, row['password_hash']))


def log_action(action, target='', result='ok', message=''):
    con = connect()
    con.execute(
        'INSERT INTO operation_logs(action,target,result,message,created_at) VALUES (?,?,?,?,?)',
        (action, target, result, message, _now()),
    )
    # Bound the operation log to 500 records; system logs remain in journald.
    con.execute(
        'DELETE FROM operation_logs WHERE id <= (SELECT MAX(id) - 500 FROM operation_logs)'
    )
    con.commit()
    con.close()
