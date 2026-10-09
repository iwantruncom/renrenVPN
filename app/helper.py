"""最小权限 root helper。

公网 Web 进程以非特权用户运行，只能通过这个 Unix socket 请求固定操作：重启
sing-box、增删经过严格校验的防火墙端口、调用固定的面板端口切换命令、启动固定的更新服务。helper 不接受
shell、任意路径或任意 systemd 服务名，并用 SO_PEERCRED 校验调用方 UID。
"""

import json
import os
import pwd
import socket
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

from . import system_ops


SOCKET_PATH = Path(os.environ.get("IVPN_HELPER_SOCKET", "/run/iwantrun-vpn/helper.sock"))
WEB_USER = os.environ.get("IVPN_WEB_USER", "iwantrun-web")
MAX_REQUEST = 4096
ALLOWED_FIREWALL_RULES = {
    (443, "tcp"), (443, "udp"), (8443, "tcp"),
    (2096, "tcp"), (2053, "udp"),
}
_PANEL_PORT_LOCK = threading.Lock()


def _run(command, timeout=30):
    process = subprocess.run(command, capture_output=True, text=True, timeout=timeout,
                             check=False)
    if process.returncode != 0:
        raise RuntimeError((process.stderr or process.stdout or "命令失败").strip())


def _firewall(operation, port, proto):
    if operation not in ("add", "remove"):
        raise ValueError("非法防火墙操作")
    if not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("非法端口")
    if proto not in ("tcp", "udp"):
        raise ValueError("非法协议")
    if (port, proto) not in ALLOWED_FIREWALL_RULES:
        raise ValueError("该端口不属于受支持的 VPN 协议")
    changed = False
    if Path("/usr/sbin/ufw").exists() or Path("/usr/bin/ufw").exists():
        command = ["ufw", "allow", f"{port}/{proto}"]
        if operation == "remove":
            command = ["ufw", "--force", "delete", "allow", f"{port}/{proto}"]
        _run(command, 20)
        changed = True
    if Path("/usr/bin/firewall-cmd").exists() or Path("/usr/sbin/firewall-cmd").exists():
        switch = "--add-port" if operation == "add" else "--remove-port"
        _run(["firewall-cmd", "--permanent", f"{switch}={port}/{proto}"], 20)
        _run(["firewall-cmd", "--reload"], 20)
        changed = True
    return {"changed": changed}


def _run_panel_port_change(port):
    try:
        time.sleep(1)
        _run([sys.executable, "-m", "app.cli", "set-port", str(port)], 60)
    except Exception as exc:
        print(f"面板端口切换失败：{exc}", flush=True)
    finally:
        _PANEL_PORT_LOCK.release()


def _schedule_panel_port(port):
    if not isinstance(port, int) or not 1024 <= port <= 65535 or port == system_ops.ACME_PORT:
        raise ValueError("面板端口必须在 1024 到 65535 之间，且不能是 80")
    old_port = system_ops.panel_port()
    if port == old_port:
        return {"scheduled": False, "old_port": old_port, "new_port": port}
    code, output, _error = system_ops.run_cmd(['ss', '-ltnH', f'sport = :{port}'], 5)
    if code == 0 and output.strip():
        raise ValueError(f"{port} 端口已被其他程序占用")
    if not _PANEL_PORT_LOCK.acquire(blocking=False):
        raise RuntimeError("另一次端口切换正在进行")
    try:
        threading.Thread(target=_run_panel_port_change, args=(port,), daemon=True).start()
    except Exception:
        _PANEL_PORT_LOCK.release()
        raise
    return {"scheduled": True, "old_port": old_port, "new_port": port}


def dispatch(request):
    if not isinstance(request, dict):
        raise ValueError("请求格式错误")
    action = request.get("action")
    if action == "restart_singbox" and set(request) == {"action"}:
        _run(["systemctl", "restart", "sing-box"], 30)
        _run(["systemctl", "is-active", "--quiet", "sing-box"], 10)
        return {"active": True}
    if action == "firewall" and set(request) == {"action", "operation", "port", "proto"}:
        return _firewall(request["operation"], request["port"], request["proto"])
    if action == "change_panel_port" and set(request) == {"action", "port"}:
        return _schedule_panel_port(request["port"])
    if action == "start_update" and set(request) == {"action"}:
        # --no-block: the update restarts this helper, so it must not wait on it.
        # Starting a oneshot that is already running is a no-op.
        _run(["systemctl", "start", "--no-block", "iwantrun-vpn-update.service"], 15)
        return {"started": True}
    raise ValueError("不支持的特权操作")


def _read_request(connection):
    connection.settimeout(10)
    data = bytearray()
    while b"\n" not in data:
        chunk = connection.recv(1024)
        if not chunk:
            break
        data.extend(chunk)
        if len(data) > MAX_REQUEST:
            raise ValueError("请求过大")
    return json.loads(bytes(data).split(b"\n", 1)[0].decode("utf-8"))


def _peer_uid(connection):
    raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    _pid, uid, _gid = struct.unpack("3i", raw)
    return uid


def serve():
    if os.geteuid() != 0:
        raise RuntimeError("root helper 必须以 root 运行")
    account = pwd.getpwnam(WEB_USER)
    SOCKET_PATH.parent.mkdir(parents=True, exist_ok=True)
    if SOCKET_PATH.exists() or SOCKET_PATH.is_symlink():
        if not SOCKET_PATH.is_socket():
            raise RuntimeError(f"helper socket 路径已被非 socket 文件占用：{SOCKET_PATH}")
        SOCKET_PATH.unlink()
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(SOCKET_PATH))
    os.chown(SOCKET_PATH, 0, account.pw_gid)
    os.chmod(SOCKET_PATH, 0o660)
    server.listen(16)
    try:
        while True:
            connection, _address = server.accept()
            with connection:
                try:
                    if _peer_uid(connection) != account.pw_uid:
                        raise PermissionError("调用者身份不正确")
                    result = dispatch(_read_request(connection))
                    response = {"ok": True, "result": result}
                except Exception as exc:
                    response = {"ok": False, "error": str(exc)[:1000]}
                connection.sendall(json.dumps(response, ensure_ascii=False).encode("utf-8") + b"\n")
    finally:
        server.close()
        if SOCKET_PATH.is_socket():
            SOCKET_PATH.unlink()


if __name__ == "__main__":
    serve()
