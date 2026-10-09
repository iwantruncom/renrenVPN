#!/bin/bash
# 人人VPN 安装程序
#
# Build and validate upgrades in a staging directory; roll back if health checks fail.
set -eE
umask 077

# Set a release or commit archive URL for reproducible installs.
# Build sing-box with with_v2ray_api; see .github/workflows/build-singbox.yml.
REPO="${IVPN_REPO:-iwantruncom/renrenVPN}"
REPO_ZIP_URL="${IVPN_REPO_ZIP_URL:-https://github.com/${REPO}/archive/refs/heads/main.zip}"
APP_DIR="/opt/iwantrun-vpn-webui"          # 永远指向当前成功版本的符号链接
RELEASE_ROOT="/opt/iwantrun-vpn-webui-releases"
DATA_DIR="/etc/freedom-vpn"                # 数据，永不删除
WEB_DATA_DIR="${DATA_DIR}/web"
SERVICE_NAME="iwantrun-vpn-web"
SB_SERVICE_NAME="sing-box"
# sing-box runs as its own unprivileged user: the web user can rewrite config.json, so
# a root sing-box would turn a panel compromise into root (log/cache paths write files).
SB_USER="iwantrun-sb"
# Root-only ACME staging and root-owned certificate store, both outside the web-owned
# DATA_DIR so the web user cannot plant symlinks for root to follow.
ACME_STAGE_DIR="/etc/iwantrun-acme"
PANEL_CERT_STORE="/etc/iwantrun-panel-cert"
TMP_DIR=""
CANDIDATE_DIR=""
ROLLBACK_DIR=""
PREVIOUS_APP=""
LEGACY_APP=""
ROLLBACK_ARMED="0"
WEB_WAS_ACTIVE="0"
SB_WAS_ACTIVE="0"
HELPER_WAS_ACTIVE="0"
FIREWALL_STATE_SAVED="0"
UFW_EXISTING_RULES=""
FIREWALLD_EXISTING_RULES=""
SB_BIN="/usr/local/bin/sing-box"
DEFAULT_SB_VER="1.14.2"
PYTHON_BIN="python3"
RESULT_FILE="${WEB_DATA_DIR}/install-result.env"
RESULT_JSON="${WEB_DATA_DIR}/install-result.json"
IVPN="${APP_DIR}/venv/bin/python -m app.cli"
ACME_VERSION="3.1.4"
# systemd units (the panel's update button) run with no HOME, and acme.sh keeps its account,
# certificates and renewal config under $HOME/.acme.sh. Without this an update from the panel
# starts a fresh /.acme.sh and reissues the certificate (Let's Encrypt allows 5 per week).
HOME="$(getent passwd 0 2>/dev/null | cut -d: -f6)"
export HOME="${HOME:-/root}"
ACME_SHA256="e5f8e187bbf5251e0cd8891f2622daab9850366bd17bea9f92c2fe2ee091fd32"

# 管理页面和订阅共用公信 HTTPS 端口；80 只用于短期 IP 证书签发与续期。
PANEL_PORT="2083"
LOGIN_PATH=""
ASSET_PATH=""
LE_ACTIVE=""          # setup_letsencrypt 成功签发后置 1，控制结尾是否还提示证书警告
ADMIN_PASS=""
ADMIN_USER="admin"
FRESH_INSTALL="1"
ACME_CONF=""          # acme.sh 域名配置；回滚时恢复，避免它指向新暂存路径而旧 hook 读旧路径

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
echo_line(){ echo -e "${CYAN}============================================================${NC}"; }
# Expected, user-actionable failure.
IVPN_DIED=0
die(){ IVPN_DIED=1; echo -e "${RED}错误：$1${NC}" >&2; exit 1; }

# Report unexpected failures from commands running under set -e.
IVPN_FAIL_LINE=0
on_unexpected_exit(){
  local code=$?
  if [[ "$code" != "0" && "$ROLLBACK_ARMED" == "1" ]]; then
    rollback_install || true
  fi
  cleanup_tmp || true
  [[ "$IVPN_DIED" == "1" || "$code" == "0" ]] && return
  echo "" >&2
  echo -e "${RED}安装没有完成（第 ${IVPN_FAIL_LINE} 行意外中断，退出码 ${code}）。${NC}" >&2
  echo -e "${YELLOW}你的数据没有丢失。直接重新运行一次同样的安装命令即可，脚本会接着装。${NC}" >&2
  echo -e "${YELLOW}如果反复失败，把上面最后几行贴给我们：https://iwantrun.com/submit${NC}" >&2
}
# -E propagates ERR traps into functions; EXIT reports the saved source line.
trap 'IVPN_FAIL_LINE=$LINENO' ERR
trap on_unexpected_exit EXIT

verify_sha256(){
  local file="$1" expected="$2" actual
  [[ "$expected" =~ ^[0-9a-fA-F]{64}$ ]] || die "安装包缺少经过审核的 SHA-256 摘要。"
  actual="$(sha256sum "$file" | awk '{print $1}')"
  [[ "${actual,,}" == "${expected,,}" ]] || die "安装包校验失败，已停止安装。"
}

init_private_tmp(){
  mkdir -p /var/tmp "$RELEASE_ROOT"
  TMP_DIR="$(mktemp -d /var/tmp/iwantrun-install.XXXXXX)" || die "无法创建安全临时目录。"
  [[ -d "$TMP_DIR" && ! -L "$TMP_DIR" && "$(stat -c %u "$TMP_DIR")" == "0" ]] \
    || die "临时目录所有权异常。"
  ROLLBACK_DIR="${TMP_DIR}/rollback"
  mkdir -p "$ROLLBACK_DIR"
}

cleanup_tmp(){
  if [[ -n "${TMP_DIR:-}" && "$TMP_DIR" == /var/tmp/iwantrun-install.* \
        && -d "$TMP_DIR" && ! -L "$TMP_DIR" ]]; then
    rm -rf -- "$TMP_DIR"
  fi
  if [[ -n "${CANDIDATE_DIR:-}" && "$CANDIDATE_DIR" == "${RELEASE_ROOT}/.staging."* \
        && -d "$CANDIDATE_DIR" && ! -L "$CANDIDATE_DIR" ]]; then
    rm -rf -- "$CANDIDATE_DIR"
  fi
}

check_root(){ [[ "$EUID" -eq 0 ]] || die "请用 root 用户运行这个脚本。"; }
validate_repo(){
  [[ "$REPO" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$ ]] \
    || die "GitHub 仓库必须写成 owner/repo。"
}

detect_arch(){
  case "$(uname -m)" in
    x86_64|amd64) echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    *) die "暂不支持这个 CPU 架构：$(uname -m)。请使用 x86_64 或 ARM64 服务器。" ;;
  esac
}

gen_secret(){
  # Generate extra characters before filtering to preserve the required length.
  openssl rand -base64 $(( $1 * 2 )) | tr -dc 'a-zA-Z0-9' | head -c "$1"
}

port_in_use(){ ss -lntu 2>/dev/null | awk '{print $5}' | grep -Eq "[:.]${1}$"; }

random_port(){
  # Select an unused high port, excluding $1.
  local avoid="${1:-}" port i
  for i in $(seq 1 20); do
    port="$(shuf -i 20000-60000 -n 1)"
    [[ "$port" == "$avoid" ]] && continue
    port_in_use "$port" && continue
    echo "$port"
    return 0
  done
  die "找不到可用的管理页面端口，请稍后再运行一次安装命令。"
}

# A freshly booted cloud image runs unattended-upgrades / cloud-init apt in the
# background and holds the dpkg lock for minutes; wait for it instead of failing.
# Prints every minute so the online installer's 5-minute idle watchdog stays fed.
APT_WAIT_LIMIT=900
# Match unattended-upgrade by argv, not `pgrep -x unattended-upgr`: the comm name is
# truncated to 15 chars, which also matches the always-resident
# `unattended-upgrade-shutdown --wait-for-signal` daemon on Ubuntu, so the wait never ended.
UU_RUNNING_RE='/unattended-upgrade( |$)'
wait_for_apt(){
  command -v pgrep >/dev/null 2>&1 || return 0
  local waited=0
  while pgrep -x 'apt|apt-get|dpkg' >/dev/null 2>&1 || pgrep -f "$UU_RUNNING_RE" >/dev/null 2>&1; do
    (( waited == 0 )) && echo -e "${YELLOW}系统正在后台自动更新，等它完成后继续（通常 1～5 分钟）...${NC}"
    (( waited >= APT_WAIT_LIMIT )) && die "系统自动更新超过 15 分钟仍未结束。请稍后重新运行安装命令。"
    sleep 10
    waited=$((waited + 10))
    (( waited % 60 == 0 )) && echo -e "${YELLOW}仍在等待系统自动更新完成...（已等 $((waited / 60)) 分钟）${NC}"
  done
  return 0
}

install_dependencies(){
  echo -e "${YELLOW}正在安装系统依赖...${NC}"
  if command -v apt-get >/dev/null 2>&1; then
    wait_for_apt
    # Lock::Timeout covers the race where a background apt grabs the lock right after the wait.
    local apt=(apt-get -o DPkg::Lock::Timeout=300)
    # Ignore unrelated third-party repository failures; apt install validates required packages.
    "${apt[@]}" update -y || echo -e "${YELLOW}提示：有软件源更新失败，继续尝试安装所需软件包。${NC}"
    DEBIAN_FRONTEND=noninteractive "${apt[@]}" install -y \
      python3 python3-venv python3-pip curl wget jq openssl iproute2 unzip tar ca-certificates socat
    command -v qrencode >/dev/null 2>&1 \
      || DEBIAN_FRONTEND=noninteractive "${apt[@]}" install -y qrencode >/dev/null 2>&1 \
      || echo -e "${YELLOW}可选的二维码工具不可用，安装将继续。${NC}"
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y wget jq openssl iproute unzip tar ca-certificates socat
    if ! command -v curl >/dev/null 2>&1; then
      dnf install -y curl-minimal || dnf install -y curl
    fi
    if python3 -c 'import sys; raise SystemExit(sys.version_info < (3, 10))' 2>/dev/null; then
      PYTHON_BIN="python3"
      dnf install -y python3-pip
    else
      dnf install -y python3.11 python3.11-pip
      PYTHON_BIN="python3.11"
    fi
    command -v qrencode >/dev/null 2>&1 \
      || dnf install -y qrencode >/dev/null 2>&1 \
      || echo -e "${YELLOW}可选的二维码工具不可用，安装将继续。${NC}"
  else
    die "暂不支持当前系统的软件包管理器；需要 apt-get 或 dnf。"
  fi
}

check_dependencies_ready(){
  echo -e "${YELLOW}正在检测运行环境...${NC}"
  local missing=()
  for cmd in "$PYTHON_BIN" curl wget jq openssl ss unzip tar socat systemctl; do
    command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
  done
  [[ "${#missing[@]}" -gt 0 ]] && die "缺少必要命令：${missing[*]}。请检查系统软件源是否可用。"
  [[ -d /run/systemd/system ]] || die "当前系统未运行 systemd，无法安装管理服务。"
  "$PYTHON_BIN" -c 'import sys; raise SystemExit(sys.version_info < (3, 10))' \
    || die "需要 Python 3.10 或更新版本。"
  "$PYTHON_BIN" -m venv --help >/dev/null 2>&1 \
    || die "Python venv 不可用，请安装所选 Python 版本的 venv 软件包。"
}

has_stats_support(){ "$1" version 2>/dev/null | grep -q with_v2ray_api; }
singbox_version(){ "$1" version 2>/dev/null | awk 'NR==1 {sub(/^v/, "", $3); print $3}'; }

install_singbox_core(){
  local arch sb_ver url expected archive extracted
  SB_STAGED=""
  if [[ -x "$SB_BIN" ]] && has_stats_support "$SB_BIN" \
     && [[ "$(singbox_version "$SB_BIN")" == "$DEFAULT_SB_VER" ]]; then
    echo -e "${GREEN}已安装 sing-box：$($SB_BIN version | head -n 1)${NC}"
    return
  fi
  [[ -x "$SB_BIN" ]] && echo -e "${YELLOW}现有内核版本或构建标签不符合目标版本，正在准备升级...${NC}"
  echo -e "${YELLOW}正在安装 sing-box...${NC}"
  arch="$(detect_arch)"
  sb_ver="$DEFAULT_SB_VER"
  SB_STAGED="${TMP_DIR}/sing-box.new"
  if [[ -n "${IVPN_SINGBOX_BIN_PATH:-}" && -s "${IVPN_SINGBOX_BIN_PATH}" ]]; then
    expected="${IVPN_SINGBOX_SHA256:-}"
    verify_sha256 "$IVPN_SINGBOX_BIN_PATH" "$expected"
    install -m 755 "$IVPN_SINGBOX_BIN_PATH" "$SB_STAGED"
  else
    case "$arch" in
      amd64) expected="${IVPN_SINGBOX_SHA256_AMD64:-}" ;;
      arm64) expected="${IVPN_SINGBOX_SHA256_ARM64:-}" ;;
    esac
    [[ -n "$expected" ]] || die "当前发布没有内置 ${arch} 内核摘要，不能安全下载。"
    url="https://github.com/${REPO}/releases/download/singbox-v${sb_ver}/sing-box-${sb_ver}-linux-${arch}.tar.gz"
    archive="${TMP_DIR}/sing-box.tar.gz"
    if ! curl -4fL --connect-timeout 15 --retry 3 -o "$archive" "$url"; then
      die "下载 sing-box 失败。请确认这台服务器能访问 GitHub。"
    fi
    verify_sha256 "$archive" "$expected"
    mkdir -p "${TMP_DIR}/sing-box-extract"
    tar -xzf "$archive" -C "${TMP_DIR}/sing-box-extract" \
      --no-same-owner --no-same-permissions || die "解压 sing-box 失败。"
    extracted="${TMP_DIR}/sing-box-extract/sing-box-${sb_ver}-linux-${arch}/sing-box"
    [[ -f "$extracted" && ! -L "$extracted" ]] || die "sing-box 安装包结构不正确。"
    install -m 755 "$extracted" "$SB_STAGED"
  fi
  has_stats_support "$SB_STAGED" || die "下载到的 sing-box 不含流量统计支持，安装中止。"
  [[ "$(singbox_version "$SB_STAGED")" == "$sb_ver" ]] \
    || die "sing-box 版本不匹配，安装中止。"
  echo -e "${GREEN}sing-box 候选版本校验完成：v${sb_ver}${NC}"
}

activate_singbox_core(){
  [[ -n "${SB_STAGED:-}" ]] || return 0
  mkdir -p "$(dirname "$SB_BIN")"
  [[ -e "$SB_BIN" ]] && cp -a "$SB_BIN" "${ROLLBACK_DIR}/sing-box.previous"
  install -m 755 "$SB_STAGED" "${SB_BIN}.new"
  mv -f "${SB_BIN}.new" "$SB_BIN"
}

cleanup_old_install(){
  echo -e "${YELLOW}正在检查旧安装并准备独立的新版本目录...${NC}"
  local known="0" unit
  if [[ -f "${WEB_DATA_DIR}/settings.json" ]] \
     && { [[ -f "${APP_DIR}/app/main.py" ]] || [[ -L "$APP_DIR" ]]; }; then
    known="1"
  fi
  if [[ "$known" != "1" ]]; then
    for unit in "/etc/systemd/system/${SERVICE_NAME}.service" \
                "/etc/systemd/system/${SB_SERVICE_NAME}.service"; do
      if [[ -e "$unit" ]] && ! grep -q '人人VPN' "$unit" 2>/dev/null; then
        die "发现同名但不属于本项目的 systemd 服务：$unit。为避免覆盖，安装已停止。"
      fi
    done
    [[ -e "$SB_BIN" ]] && die "${SB_BIN} 已存在且无法确认属于本项目，请先备份并移走。"
    [[ -e /usr/local/bin/renrenvpn ]] \
      && die "/usr/local/bin/renrenvpn 已存在且无法确认属于本项目。"
    if port_in_use 443; then
      die "443 端口已被其他程序占用。请先确认并停用它，安装器不会强制覆盖。"
    fi
  fi
  mkdir -p "$RELEASE_ROOT" "$WEB_DATA_DIR"
}

download_project(){
  local archive="${TMP_DIR}/source.zip" expected=""
  CANDIDATE_DIR="$(mktemp -d "${RELEASE_ROOT}/.staging.XXXXXX")" \
    || die "无法创建新版本目录。"
  # Prefer a verified source archive supplied by the online installer when present.
  if [[ -n "${IVPN_REPO_ZIP_PATH:-}" && -s "${IVPN_REPO_ZIP_PATH}" ]]; then
    echo -e "${YELLOW}正在使用安装器上传的管理面板源码...${NC}"
    expected="${IVPN_REPO_ZIP_SHA256:-}"
    cp "$IVPN_REPO_ZIP_PATH" "$archive"
  else
    echo -e "${YELLOW}正在下载管理面板...${NC}"
    expected="${IVPN_REPO_ZIP_SHA256:-}"
    [[ -n "$expected" ]] || die "当前发布没有内置源码摘要，不能安全下载。"
    wget -q --tries=3 -O "$archive" "$REPO_ZIP_URL" || die "下载面板源码失败。"
  fi
  verify_sha256 "$archive" "$expected"
  mkdir -p "${TMP_DIR}/source"
  unzip -q "$archive" -d "${TMP_DIR}/source" || die "源码包损坏，解压失败。请重新运行安装命令。"
  local src=""
  # Accept GitHub's top-level directory or a flat source archive.
  if [[ -d "${TMP_DIR}/source/app" && -f "${TMP_DIR}/source/requirements.txt" ]]; then
    src="${TMP_DIR}/source"
  else
    local d
    # Use a loop rather than a pipeline so set -e does not exit before the error check.
    for d in "${TMP_DIR}/source"/*/; do
      if [[ -d "${d}app" && -f "${d}requirements.txt" ]]; then
        src="${d%/}"
        break
      fi
    done
  fi
  [[ -z "$src" ]] && die "源码包里没有找到 app/ 和 requirements.txt。请重新运行安装命令。"
  cp -a "$src/app" "$CANDIDATE_DIR/"
  cp "$src/requirements.txt" "$CANDIDATE_DIR/"
  [[ -f "$src/requirements.lock" ]] && cp "$src/requirements.lock" "$CANDIDATE_DIR/"
}

install_python_env(){
  echo -e "${YELLOW}正在准备 Python 环境...${NC}"
  cd "$CANDIDATE_DIR"
  "$PYTHON_BIN" -m venv venv
  [[ -x "$CANDIDATE_DIR/venv/bin/pip" ]] || "$CANDIDATE_DIR/venv/bin/python" -m ensurepip --upgrade || true
  [[ -x "$CANDIDATE_DIR/venv/bin/pip" ]] || die "Python 虚拟环境创建失败，未找到 pip。"
  [[ -f "$CANDIDATE_DIR/requirements.lock" ]] \
    || die "源码包缺少带哈希的 requirements.lock，已停止安装。"
  "$CANDIDATE_DIR/venv/bin/pip" install -q --require-hashes -r requirements.lock
  mkdir -p "${TMP_DIR}/validation-data"
  cd "$CANDIDATE_DIR" && IVPN_DATA_DIR="${TMP_DIR}/validation-data" IVPN_PREVIEW=1 \
    "$CANDIDATE_DIR/venv/bin/python" -c 'import app.main, app.serve, app.cli'
}

snapshot_file(){
  local path="$1" name="$2"
  if [[ -e "$path" || -L "$path" ]]; then
    cp -a "$path" "${ROLLBACK_DIR}/${name}"
    : > "${ROLLBACK_DIR}/${name}.existed"
  fi
}

restore_file(){
  local path="$1" name="$2"
  if [[ -f "${ROLLBACK_DIR}/${name}.existed" ]]; then
    cp -a "${ROLLBACK_DIR}/${name}" "${path}.rollback"
    mv -f "${path}.rollback" "$path"
  else
    rm -f -- "$path"
  fi
}

snapshot_install(){
  systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null && WEB_WAS_ACTIVE="1"
  systemctl is-active --quiet "$SB_SERVICE_NAME" 2>/dev/null && SB_WAS_ACTIVE="1"
  systemctl is-active --quiet iwantrun-vpn-helper 2>/dev/null && HELPER_WAS_ACTIVE="1"
  systemctl stop "$SERVICE_NAME" 2>/dev/null || true
  systemctl stop "$SB_SERVICE_NAME" 2>/dev/null || true
  systemctl stop iwantrun-vpn-helper 2>/dev/null || true

  snapshot_file "/etc/systemd/system/${SERVICE_NAME}.service" web.service
  snapshot_file "/etc/systemd/system/${SB_SERVICE_NAME}.service" sing-box.service
  snapshot_file /etc/systemd/system/iwantrun-vpn-helper.service helper.service
  snapshot_file /etc/systemd/system/iwantrun-cert-renew.service cert-renew.service
  snapshot_file /etc/systemd/system/iwantrun-cert-renew.timer cert-renew.timer
  snapshot_file /etc/systemd/system/iwantrun-vpn-update.service update.service
  snapshot_file /usr/local/bin/ivpn ivpn
  snapshot_file /usr/local/bin/renrenvpn renrenvpn
  snapshot_file /usr/local/libexec/iwantrun-activate-panel-cert cert-hook
  snapshot_file /usr/local/libexec/iwantrun-renew-panel-cert cert-renew-hook
  snapshot_file "$SB_BIN" sing-box
  if [[ -d "$DATA_DIR" ]]; then
    cp -a "$DATA_DIR" "${ROLLBACK_DIR}/data"
    : > "${ROLLBACK_DIR}/data.existed"
  fi
  if [[ -L "$APP_DIR" ]]; then
    PREVIOUS_APP="$(readlink -f "$APP_DIR")"
  fi
  ROLLBACK_ARMED="1"
}

activate_release(){
  local release_id target link_tmp
  release_id="$(date -u +%Y%m%dT%H%M%SZ)-$(openssl rand -hex 6)"
  target="${RELEASE_ROOT}/${release_id}"
  mv "$CANDIDATE_DIR" "$target"
  CANDIDATE_DIR="$target"

  if [[ -d "$APP_DIR" && ! -L "$APP_DIR" ]]; then
    LEGACY_APP="${RELEASE_ROOT}/legacy-${release_id}"
    mv "$APP_DIR" "$LEGACY_APP"
    PREVIOUS_APP="$LEGACY_APP"
  fi
  link_tmp="${APP_DIR}.new.$$"
  ln -s "$target" "$link_tmp"
  mv -Tf "$link_tmp" "$APP_DIR"
}

rollback_install(){
  local failed_release=""
  ROLLBACK_ARMED="0"
  set +e
  echo -e "${YELLOW}新版本未通过检查，正在恢复上一版...${NC}" >&2
  systemctl stop "$SERVICE_NAME" >/dev/null 2>&1
  systemctl stop "$SB_SERVICE_NAME" >/dev/null 2>&1
  systemctl stop iwantrun-vpn-helper >/dev/null 2>&1

  [[ -L "$APP_DIR" ]] && failed_release="$(readlink -f "$APP_DIR")"
  if [[ -n "$PREVIOUS_APP" && -d "$PREVIOUS_APP" ]]; then
    if [[ -n "$LEGACY_APP" ]]; then
      rm -f -- "$APP_DIR"
      mv "$LEGACY_APP" "$APP_DIR"
    else
      ln -s "$PREVIOUS_APP" "${APP_DIR}.rollback.$$"
      mv -Tf "${APP_DIR}.rollback.$$" "$APP_DIR"
    fi
  else
    rm -f -- "$APP_DIR"
  fi

  if [[ -d "$DATA_DIR" ]]; then
    mv "$DATA_DIR" "${TMP_DIR}/failed-data" 2>/dev/null || true
  fi
  if [[ -f "${ROLLBACK_DIR}/data.existed" ]]; then
    cp -a "${ROLLBACK_DIR}/data" "$DATA_DIR"
  fi
  restore_file "/etc/systemd/system/${SERVICE_NAME}.service" web.service
  restore_file "/etc/systemd/system/${SB_SERVICE_NAME}.service" sing-box.service
  restore_file /etc/systemd/system/iwantrun-vpn-helper.service helper.service
  restore_file /etc/systemd/system/iwantrun-cert-renew.service cert-renew.service
  restore_file /etc/systemd/system/iwantrun-cert-renew.timer cert-renew.timer
  restore_file /etc/systemd/system/iwantrun-vpn-update.service update.service
  restore_file /usr/local/bin/ivpn ivpn
  restore_file /usr/local/bin/renrenvpn renrenvpn
  restore_file /usr/local/libexec/iwantrun-activate-panel-cert cert-hook
  restore_file /usr/local/libexec/iwantrun-renew-panel-cert cert-renew-hook
  restore_file "$SB_BIN" sing-box
  [[ -n "$ACME_CONF" && -f "${ROLLBACK_DIR}/acme.conf.existed" ]] && restore_file "$ACME_CONF" acme.conf
  rollback_firewall_rules
  systemctl daemon-reload >/dev/null 2>&1
  [[ "$SB_WAS_ACTIVE" == "1" ]] && systemctl start "$SB_SERVICE_NAME" >/dev/null 2>&1
  [[ "$HELPER_WAS_ACTIVE" == "1" ]] && systemctl start iwantrun-vpn-helper >/dev/null 2>&1
  [[ "$WEB_WAS_ACTIVE" == "1" ]] && systemctl start "$SERVICE_NAME" >/dev/null 2>&1

  if [[ -n "$failed_release" && "$failed_release" == "${RELEASE_ROOT}/"* \
        && "$failed_release" != "$PREVIOUS_APP" && -d "$failed_release" ]]; then
    mv "$failed_release" "${TMP_DIR}/failed-release" 2>/dev/null || true
  fi
  echo -e "${GREEN}已恢复安装前的程序、配置、内核和服务状态。${NC}" >&2
}

panel_has_admin(){
  cd "$APP_DIR" && "$APP_DIR/venv/bin/python" -c \
    'from app import db; db.init_db(); raise SystemExit(0 if db.has_admin() else 1)' 2>/dev/null
}

resolve_identity(){
  if panel_has_admin; then
    # Preserve access settings; rotate credentials after installation checks pass.
    FRESH_INSTALL="0"
    LOGIN_PATH="$(jq -r '.login_path // empty' "${WEB_DATA_DIR}/settings.json" 2>/dev/null)"
    PANEL_PORT="$(jq -r '.panel_port // empty' "${WEB_DATA_DIR}/settings.json" 2>/dev/null)"
    ASSET_PATH="$(jq -r '.asset_path // empty' "${WEB_DATA_DIR}/settings.json" 2>/dev/null)"
    [[ -z "$LOGIN_PATH" ]] && LOGIN_PATH="login-$(openssl rand -hex 16)"
    [[ -z "$PANEL_PORT" ]] && PANEL_PORT="$(random_port 80)"
    [[ "$ASSET_PATH" =~ ^assets-[0-9a-fA-F]{32}$ ]] \
      || ASSET_PATH="assets-$(openssl rand -hex 16)"
    ADMIN_USER="$(cd "$APP_DIR" && "$APP_DIR/venv/bin/python" -c \
      'from app import db; print(db.admin_username())')" \
      || die "读取管理账号失败。"
    [[ -n "$ADMIN_USER" ]] || die "管理账号为空。"
    if [[ "${IVPN_ONLINE_INSTALL:-0}" == "1" ]]; then
      echo -e "${GREEN}检测到已有安装：保留用户、设置和访问地址，安装成功后生成新的管理密码。${NC}"
    else
      echo -e "${GREEN}检测到已有安装：保留用户、设置、访问地址和管理密码。${NC}"
    fi
  else
    FRESH_INSTALL="1"
    LOGIN_PATH="login-$(openssl rand -hex 16)"
    ASSET_PATH="assets-$(openssl rand -hex 16)"
    ADMIN_PASS="$(gen_secret 18)"
    # Use a random management port and login path; reserve port 80 for ACME.
    PANEL_PORT="$(random_port 80)"
  fi

  mkdir -p "$WEB_DATA_DIR"
  cat > "${WEB_DATA_DIR}/settings.json" <<EOJ
{"panel_port": ${PANEL_PORT}, "login_path": "${LOGIN_PATH}", "asset_path": "${ASSET_PATH}"}
EOJ

  if [[ "$FRESH_INSTALL" == "1" ]]; then
    # Password goes over stdin; argv is world-readable in /proc.
    printf '%s\n' "$ADMIN_PASS" | (cd "$APP_DIR" && $IVPN init-admin admin) >/dev/null \
      || die "创建管理账号失败。"
  fi
  local saved_repo
  saved_repo="$(cd "$APP_DIR" && "$APP_DIR/venv/bin/python" -c \
    'from app import db; print(db.get_setting("update_repo"))')" \
    || die "读取现有更新仓库失败。"
  if [[ -n "${IVPN_REPO:-}" || -z "$saved_repo" \
        || "$saved_repo" == "iwantruncom/iwantrun.com-VPN-Web-Manager" ]]; then
    cd "$APP_DIR" && $IVPN set-update-repo "$REPO" >/dev/null
  fi
  # Show the version in the panel; renrenvpn update records its own tag afterwards.
  if [[ "$REPO_ZIP_URL" =~ /releases/download/((vpn-)?v[0-9]+\.[0-9]+\.[0-9]+)/ ]]; then
    (cd "$APP_DIR" && "$APP_DIR/venv/bin/python" -c \
      'import sys; from app import db; db.set_setting("installed_release", sys.argv[1])' \
      "${BASH_REMATCH[1]}") || die "记录面板版本失败。"
  fi
}

rotate_install_password(){
  [[ "$FRESH_INSTALL" == "0" ]] || return 0
  # Only a renrenvpn.com reinstall rotates (it is how a locked-out owner recovers);
  # renrenvpn update, the panel's update button and SSH reruns keep password and sessions.
  [[ "${IVPN_ONLINE_INSTALL:-0}" == "1" ]] || return 0
  ADMIN_PASS="$(gen_secret 18)"
  printf '%s\n' "$ADMIN_PASS" | (
    cd "$APP_DIR" && "$APP_DIR/venv/bin/python" -c \
      'import sys; from app import db; db.create_admin(db.admin_username(), sys.stdin.readline().rstrip("\n")); db.bump_session_epoch()'
  ) || die "重置管理密码失败。"
}

write_unit(){
  # Validate a temporary unit before atomically replacing the active file.
  local dest="$1" content="$2" tmp="$1.tmp.$$"
  printf '%s' "$content" > "$tmp"
  [[ -s "$tmp" ]] || { rm -f "$tmp"; die "写入 $dest 失败。"; }
  mv -f "$tmp" "$dest"
  chmod 644 "$dest"
}

ensure_system_user(){
  getent group "$1" >/dev/null 2>&1 || groupadd --system "$1"
  id -u "$1" >/dev/null 2>&1 || useradd --system --gid "$1" \
    --home-dir /nonexistent --shell /usr/sbin/nologin "$1"
}

fix_data_perms(){
  # Idempotent; also migrates old installs (root sing-box, 0600 files in singbox/).
  # chown/chgrp -R do not follow symlinks; find -type f skips them.
  local sb_dir="${DATA_DIR}/singbox"
  mkdir -p "$sb_dir"
  chown -R iwantrun-web:iwantrun-web "$DATA_DIR"
  chmod 700 "$DATA_DIR" "$WEB_DATA_DIR"
  # setgid: files the panel creates here inherit the sing-box group (see singbox._share_with_core).
  chgrp -R "$SB_USER" "$sb_dir"
  chmod 2750 "$sb_dir"
  find "$sb_dir" -maxdepth 1 -type f -exec chmod 640 {} +
}

create_services(){
  echo -e "${YELLOW}正在注册系统服务...${NC}"
  ensure_system_user iwantrun-web
  ensure_system_user "$SB_USER"
  # Keep release code root-owned while allowing the unprivileged services to read it.
  chgrp iwantrun-web "$RELEASE_ROOT"
  chmod 750 "$RELEASE_ROOT"
  chgrp -R iwantrun-web "$CANDIDATE_DIR"
  chmod -R g+rX "$CANDIDATE_DIR"
  fix_data_perms
  install -d -o root -g iwantrun-web -m 750 "$PANEL_CERT_STORE" "${PANEL_CERT_STORE}/versions"
  # Bound restart attempts to avoid endless crash loops.
  write_unit "/etc/systemd/system/${SB_SERVICE_NAME}.service" "[Unit]
Description=sing-box (人人VPN)
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=180
StartLimitBurst=10

[Service]
Type=simple
User=${SB_USER}
Group=${SB_USER}
ExecStart=${SB_BIN} run -c ${DATA_DIR}/singbox/config.json
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5
LimitNOFILE=infinity
# Server only (no tun): binding 443 is the one privilege it needs.
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
LockPersonality=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
# Hide panel.db and the rest of DATA_DIR (which is 0700 to the web user anyway);
# expose only singbox/ read-only at its usual path. Nothing is writable.
TemporaryFileSystem=${DATA_DIR}:ro
BindReadOnlyPaths=${DATA_DIR}/singbox

[Install]
WantedBy=multi-user.target
"

  write_unit "/etc/systemd/system/${SERVICE_NAME}.service" "[Unit]
Description=人人VPN Web Manager
After=network-online.target iwantrun-vpn-helper.service
Wants=network-online.target iwantrun-vpn-helper.service
StartLimitIntervalSec=180
StartLimitBurst=10

[Service]
Type=simple
User=iwantrun-web
Group=iwantrun-web
# Restrict permissions on files created by the panel, including its database and keys.
UMask=0077
WorkingDirectory=${APP_DIR}
# The panel and subscriptions share HTTPS; access logs are disabled to protect tokens.
ExecStart=${APP_DIR}/venv/bin/python -m app.serve
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
LockPersonality=true
RestrictSUIDSGID=true
CapabilityBoundingSet=
# The cert store is root-owned; only serve.py's chmod on its own key needs it writable.
ReadWritePaths=${DATA_DIR} ${PANEL_CERT_STORE}

[Install]
WantedBy=multi-user.target
"

  write_unit "/etc/systemd/system/iwantrun-vpn-helper.service" "[Unit]
Description=人人VPN restricted privilege helper
After=network.target
Before=${SERVICE_NAME}.service

[Service]
Type=simple
User=root
Group=iwantrun-web
UMask=0007
RuntimeDirectory=iwantrun-vpn
RuntimeDirectoryMode=0750
WorkingDirectory=${APP_DIR}
ExecStart=${APP_DIR}/venv/bin/python -m app.helper
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ProtectSystem=strict
ReadWritePaths=${DATA_DIR} -/etc/ufw -/etc/firewalld -/var/lib/ufw -/var/lib/firewalld
LockPersonality=true
RestrictSUIDSGID=true
RestrictAddressFamilies=AF_UNIX AF_NETLINK
# CAP_CHOWN: set-port rewrites settings.json as root and must hand it back to the panel user.
CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_CHOWN CAP_NET_ADMIN CAP_NET_RAW

[Install]
WantedBy=multi-user.target
"
  # The panel's update button: the helper starts this unit, so the update runs outside
  # (and survives restarting) the web, helper and sing-box services it replaces.
  write_unit /etc/systemd/system/iwantrun-vpn-update.service "[Unit]
Description=人人VPN update from the signed GitHub release

[Service]
Type=oneshot
ExecStart=/usr/local/bin/renrenvpn update
"
  systemctl daemon-reload
  systemctl enable "$SB_SERVICE_NAME" >/dev/null 2>&1
  systemctl enable iwantrun-vpn-helper >/dev/null 2>&1
  systemctl enable "$SERVICE_NAME" >/dev/null 2>&1
}

install_cli(){
  # Keep the recovery CLI available when the panel service is down.
  write_unit /usr/local/bin/renrenvpn "#!/bin/bash
cd ${APP_DIR} || exit 1
exec ${APP_DIR}/venv/bin/python -m app.cli \"\$@\"
"
  chmod 755 /usr/local/bin/renrenvpn
  if [[ -f /usr/local/bin/ivpn ]] \
     && grep -Fq 'python -m app.cli' /usr/local/bin/ivpn 2>/dev/null; then
    rm -f -- /usr/local/bin/ivpn
  fi
}

prepare_vpn(){
  echo -e "${YELLOW}正在准备连接方式（会实测挑选伪装域名，约需十秒）...${NC}"
  cd "$APP_DIR"
  $IVPN install || die "连接方式准备失败。请重新运行一次安装命令。"
  open_firewall
  fix_data_perms
}

product_firewall_rules(){
  # Keep this rollback list in sync with app/singbox.py; do not modify unrelated ports.
  printf '%s\n' \
    "443 tcp" "443 udp" "8443 tcp" "2096 tcp" "2053 udp" \
    "${PANEL_PORT} tcp" "80 tcp"
}

snapshot_firewall_rules(){
  local port proto spec
  FIREWALL_STATE_SAVED="1"
  while read -r port proto; do
    spec="${port}/${proto}"
    if command -v ufw >/dev/null 2>&1 \
       && ufw status 2>/dev/null | awk -v rule="$spec" \
            '$1 == rule && $2 == "ALLOW" { found=1 } END { exit !found }'; then
      UFW_EXISTING_RULES+=" ${spec} "
    fi
    if command -v firewall-cmd >/dev/null 2>&1 \
       && firewall-cmd --permanent --query-port="$spec" >/dev/null 2>&1; then
      FIREWALLD_EXISTING_RULES+=" ${spec} "
    fi
  done < <(product_firewall_rules)
}

rollback_firewall_rules(){
  [[ "$FIREWALL_STATE_SAVED" == "1" ]] || return 0
  local port proto spec firewalld_changed="0"
  while read -r port proto; do
    spec="${port}/${proto}"
    if command -v ufw >/dev/null 2>&1 && [[ "$UFW_EXISTING_RULES" != *" ${spec} "* ]]; then
      ufw --force delete allow "$spec" >/dev/null 2>&1 || true
    fi
    if command -v firewall-cmd >/dev/null 2>&1 \
       && [[ "$FIREWALLD_EXISTING_RULES" != *" ${spec} "* ]]; then
      firewall-cmd --permanent --remove-port="$spec" >/dev/null 2>&1 || true
      firewalld_changed="1"
    fi
  done < <(product_firewall_rules)
  if [[ "$firewalld_changed" == "1" ]]; then
    firewall-cmd --reload >/dev/null 2>&1 || true
  fi
}

open_firewall(){
  local port
  # Port 80 serves ACME HTTP-01; PANEL_PORT serves the panel and subscriptions.
  for port in "$PANEL_PORT" 80; do
    if command -v ufw >/dev/null 2>&1; then
      ufw allow "${port}/tcp" >/dev/null 2>&1 || die "ufw 放行 ${port}/tcp 失败。"
    fi
    if command -v firewall-cmd >/dev/null 2>&1; then
      firewall-cmd --permanent --add-port="${port}/tcp" >/dev/null 2>&1 \
        || die "firewalld 放行 ${port}/tcp 失败。"
    fi
  done
  if command -v firewall-cmd >/dev/null 2>&1; then
    firewall-cmd --reload >/dev/null 2>&1 || die "firewalld 重载失败。"
  fi
}

link_panel_cert(){
  # serve.py reads web/panel-cert-current; point it once at the root-owned "current"
  # link so renewals never write into the web-owned tree. Built in a root dir, then
  # renamed (rename replaces a symlink, never follows it). Also migrates old layouts.
  local tmp="${PANEL_CERT_STORE}/.web-link.$$"
  ln -s "${PANEL_CERT_STORE}/current" "$tmp"
  mv -Tf "$tmp" "${WEB_DATA_DIR}/panel-cert-current" || die "无法启用面板证书。"
  rm -rf -- "${WEB_DATA_DIR}/panel-cert-versions" "${WEB_DATA_DIR}/panel-cert-acme-stage"
}

setup_letsencrypt(){
  # Never expose password or subscription endpoints without a trusted certificate.
  local host acme extra=() acme_archive acme_src acme_stage hook renew_hook
  host="$(cd "$APP_DIR" && "$APP_DIR/venv/bin/python" -c \
    'from app import singbox; print(singbox.public_host())' 2>/dev/null)"
  if [[ -z "$host" || "$host" == "SERVER_IP" || "$host" == "localhost" ]]; then
    die "没有探测到公网 IP，无法申请可信 HTTPS 证书。"
  fi
  "$APP_DIR/venv/bin/python" -c \
    'import ipaddress,sys; raise SystemExit(0 if ipaddress.ip_address(sys.argv[1]).version == 4 else 1)' \
    "$host" || die "当前安装器只支持有公网 IPv4 的服务器。"
  # ACME HTTP-01 requires port 80.
  if ss -tlnH 'sport = :80' 2>/dev/null | grep -q .; then
    die "80 端口被占用，无法申请可信 HTTPS 证书。"
  fi
  echo -e "${YELLOW}正在申请 Let's Encrypt 证书（约需十几秒）...${NC}"
  # socat is required by standalone mode and installed during dependency setup.
  command -v socat >/dev/null 2>&1 || die "缺少 socat，无法进行证书验证。"
  # Reinstall a pinned, verified acme.sh build instead of trusting an existing executable.
  acme_archive="${TMP_DIR}/acme.sh-${ACME_VERSION}.tar.gz"
  curl -fsSL --connect-timeout 15 --retry 3 \
    -o "$acme_archive" \
    "https://codeload.github.com/acmesh-official/acme.sh/tar.gz/refs/tags/${ACME_VERSION}" \
    || die "无法下载证书客户端。"
  verify_sha256 "$acme_archive" "$ACME_SHA256"
  mkdir -p "${TMP_DIR}/acme-src"
  tar -xzf "$acme_archive" -C "${TMP_DIR}/acme-src" --no-same-owner --no-same-permissions
  acme_src="${TMP_DIR}/acme-src/acme.sh-${ACME_VERSION}"
  [[ -x "${acme_src}/acme.sh" ]] || die "证书客户端安装包结构不正确。"
  (cd "$acme_src" && ./acme.sh --install --home "$HOME/.acme.sh" --no-cron) >/dev/null 2>&1 \
    || die "证书客户端安装失败。"
  acme="$HOME/.acme.sh/acme.sh"
  [[ -x "$acme" ]] || die "证书客户端安装失败。"

  # Use staging only for tests; IP short-lived certificates require Let's Encrypt.
  if [[ -n "${IVPN_ACME_STAGING:-}" ]]; then extra+=(--staging); else extra+=(--server letsencrypt); fi

  # Everything root touches here is root-owned and outside the web-owned DATA_DIR,
  # so a compromised web user cannot plant symlinks for root to follow.
  acme_stage="$ACME_STAGE_DIR"
  install -d -o root -g root -m 700 "$acme_stage"
  install -d -o root -g iwantrun-web -m 750 "$PANEL_CERT_STORE" "${PANEL_CERT_STORE}/versions"
  mkdir -p /usr/local/libexec
  hook="/usr/local/libexec/iwantrun-activate-panel-cert"
  cat > "$hook" <<EOF
#!/bin/bash
set -eE
umask 077
host='$host'
stage='$acme_stage'
store='${PANEL_CERT_STORE}'
root="\${store}/versions"
current="\${store}/current"
cert="\${stage}/fullchain.pem"
key="\${stage}/key.pem"
# Refuse to run unless every path is a real, root-owned directory/file (no symlinks).
for d in "\$stage" "\$store" "\$root"; do
  [[ -d "\$d" && ! -L "\$d" && "\$(stat -c %u "\$d")" == 0 ]] || exit 1
done
[[ -f "\$cert" && ! -L "\$cert" && -s "\$cert" && -f "\$key" && ! -L "\$key" && -s "\$key" ]] || exit 1
openssl x509 -in "\$cert" -checkend 86400 -noout
openssl x509 -in "\$cert" -checkip "\$host" -noout
[[ "\$(openssl x509 -in "\$cert" -noout -subject)" != "\$(openssl x509 -in "\$cert" -noout -issuer)" ]]
cert_pub="\$(openssl x509 -in "\$cert" -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum | awk '{print \$1}')"
key_pub="\$(openssl pkey -in "\$key" -pubout -outform DER | sha256sum | awk '{print \$1}')"
[[ "\$cert_pub" == "\$key_pub" ]]
if [[ -s "\${current}/fullchain.pem" && -s "\${current}/key.pem" ]] \\
   && cmp -s "\$cert" "\${current}/fullchain.pem" \\
   && cmp -s "\$key" "\${current}/key.pem"; then
  exit 0
fi
version="\$root/\$(date -u +%Y%m%dT%H%M%SZ)-\$(openssl rand -hex 4)"
mkdir -m 750 "\$version"
chgrp iwantrun-web "\$version"
# The panel owns its copies (serve.py chmods the key); the directories stay root's.
install -m 600 -o iwantrun-web -g iwantrun-web "\$cert" "\$version/fullchain.pem"
install -m 600 -o iwantrun-web -g iwantrun-web "\$key" "\$version/key.pem"
ln -s "\$version" "\${current}.new.\$\$"
mv -Tf "\${current}.new.\$\$" "\$current"
systemctl is-active --quiet ${SERVICE_NAME} && systemctl restart ${SERVICE_NAME} || true
EOF
  chmod 700 "$hook"

  ACME_CONF="$HOME/.acme.sh/${host}_ecc/${host}.conf"
  snapshot_file "$ACME_CONF" acme.conf

  # Use the short-lived profile for IP certificates and revalidate existing certificates.
  if "$acme" --issue -d "$host" --standalone --httpport 80 \
       --keylength ec-256 --cert-profile shortlived --days 3 "${extra[@]}" >/dev/null 2>&1 \
     || [[ -s "$HOME/.acme.sh/${host}_ecc/fullchain.cer" || -s "$HOME/.acme.sh/${host}/fullchain.cer" ]]; then
    "$acme" --install-cert -d "$host" --ecc \
      --key-file "${acme_stage}/key.pem" \
      --fullchain-file "${acme_stage}/fullchain.pem" \
      --reloadcmd "$hook" >/dev/null 2>&1 \
      || die "证书已签发，但安全安装失败。"
    "$hook" || die "证书身份、有效期或私钥匹配检查失败。"
    link_panel_cert
    LE_ACTIVE=1
    echo -e "${GREEN}已启用 Let's Encrypt 证书，浏览器不再报证书警告。${NC}"
  else
    die "证书申请失败；未开放密码登录。请检查公网 IP、80/TCP 和签发限额。"
  fi

  renew_hook="/usr/local/libexec/iwantrun-renew-panel-cert"
  cat > "$renew_hook" <<EOF
#!/bin/bash
set -u
status=0
"${acme}" --cron --home "${HOME}/.acme.sh" || status=1
cert='${PANEL_CERT_STORE}/current/fullchain.pem'
if ! openssl x509 -in "\$cert" -checkend 86400 -noout; then
  echo '人人VPN 面板证书不足 24 小时或无法读取' >&2
  exit 1
fi
exit "\$status"
EOF
  chmod 700 "$renew_hook"

  write_unit /etc/systemd/system/iwantrun-cert-renew.service "[Unit]
Description=Renew 人人VPN short-lived IP certificate
After=network-online.target

[Service]
Type=oneshot
ExecStart=${renew_hook}
"
  write_unit /etc/systemd/system/iwantrun-cert-renew.timer "[Unit]
Description=Check 人人VPN IP certificate renewal every six hours

[Timer]
OnCalendar=*-*-* 00/6:17:00
RandomizedDelaySec=20m
Persistent=true

[Install]
WantedBy=timers.target
"
  systemctl daemon-reload
  systemctl enable --now iwantrun-cert-renew.timer >/dev/null 2>&1
}

enable_bbr(){
  # BBR affects TCP only; Hysteria2 uses QUIC congestion control.
  local sysctl_conf="/etc/sysctl.d/99-iwantrun-bbr.conf"

  modprobe tcp_bbr 2>/dev/null || true
  # Containers without kernel control may skip this optional tuning.
  if ! grep -qw bbr /proc/sys/net/ipv4/tcp_available_congestion_control 2>/dev/null; then
    echo -e "${YELLOW}这台机器的内核不支持 BBR，已跳过（不影响使用）。${NC}"
    return 0
  fi

  # Replace the file on each run instead of appending duplicate settings.
  cat > "$sysctl_conf" <<'SYSCTL'
# Remove this file to restore system defaults.
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
SYSCTL
  # Load tcp_bbr before applying sysctl settings at boot.
  echo tcp_bbr > /etc/modules-load.d/iwantrun-bbr.conf
  sysctl --system >/dev/null 2>&1 || true

  local now
  now="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)"
  if [[ "$now" == "bbr" ]]; then
    echo -e "${GREEN}已启用 BBR 加速。${NC}"
  else
    echo -e "${YELLOW}BBR 没有生效（当前为 ${now:-未知}），不影响使用。${NC}"
  fi
}

tune_udp_buffers(){
  # Non-root sing-box lacks CAP_NET_ADMIN, so quic-go (Hysteria2/TUIC) can no longer force
  # 7.5 MB UDP buffers past net.core.*mem_max; raise the limits instead. Optional tuning.
  local conf="/etc/sysctl.d/99-iwantrun-udp.conf" key cur want=7500000 body=""
  for key in net.core.rmem_max net.core.wmem_max; do
    cur="$(sysctl -n "$key" 2>/dev/null || echo 0)"
    [[ "$cur" =~ ^[0-9]+$ && "$cur" -ge "$want" ]] || body+="${key}=${want}"$'\n'
  done
  [[ -n "$body" ]] || return 0
  printf '# Remove this file to restore system defaults.\n%s' "$body" > "$conf" 2>/dev/null || return 0
  sysctl -p "$conf" >/dev/null 2>&1 || true
}

start_services(){
  systemctl restart "$SB_SERVICE_NAME" || true
  systemctl restart iwantrun-vpn-helper
  systemctl restart "$SERVICE_NAME"
}

verify_services(){
  # Report success only after the service passes its health check.
  echo -e "${YELLOW}正在确认服务已经启动...${NC}"
  local i
  systemctl is-active --quiet iwantrun-vpn-helper \
    || die "权限助手没有启动，管理页面不能安全地应用配置。"
  for i in $(seq 1 10); do
    systemctl is-active --quiet "$SERVICE_NAME" && break
    if [[ $i -eq 10 ]]; then
      journalctl -u "$SERVICE_NAME" -n 40 --no-pager || true
      die "管理页面服务没有启动。上面是它的日志。"
    fi
    sleep 1
  done
  # sing-box has no inbound until the first user is added.
  if jq -e '(.inbounds // []) | length > 0' "${DATA_DIR}/singbox/config.json" >/dev/null 2>&1; then
    for i in $(seq 1 10); do
      systemctl is-active --quiet "$SB_SERVICE_NAME" && break
      if [[ $i -eq 10 ]]; then
        journalctl -u "$SB_SERVICE_NAME" -n 40 --no-pager || true
        die "VPN 服务没有启动。上面是它的日志。"
      fi
      sleep 1
    done
  fi
}

verify_panel_https(){
  local host url body attempt
  host="$(cd "$APP_DIR" && "$APP_DIR/venv/bin/python" -c \
    'from app import singbox; print(singbox.public_host())' 2>/dev/null)"
  url="$(panel_url)"
  body="${TMP_DIR}/panel-health.html"
  for attempt in $(seq 1 10); do
    if curl --fail --silent --max-time 5 --noproxy '*' \
      --resolve "${host}:${PANEL_PORT}:127.0.0.1" -o "$body" "$url"; then
      break
    fi
    [[ "$attempt" -eq 10 ]] && die "管理页面 HTTPS 身份或本机健康检查失败。"
    sleep 1
  done
  grep -Fq "action=\"/${LOGIN_PATH}\"" "$body" \
    || die "管理页面返回内容不正确，已恢复上一版。"
}

panel_url(){
  local host authority
  host="$(cd "$APP_DIR" && "$APP_DIR/venv/bin/python" -c \
    'from app import singbox; print(singbox.public_host())' 2>/dev/null)"
  [[ -z "$host" || "$host" == "SERVER_IP" ]] && host="你的服务器 IP"
  authority="$host"
  [[ "$host" == *:* && "$host" != \[*\] ]] && authority="[$host]"
  echo "https://${authority}:${PANEL_PORT}/${LOGIN_PATH}"
}

write_install_result(){
  # Record the current installation credentials in root-only files.
  # printf %q safely escapes values for later shell sourcing.
  local url firewall json_tmp env_tmp
  url="$(panel_url)"
  firewall="$( { cd "$APP_DIR" 2>/dev/null && $IVPN info 2>/dev/null || true; } \
    | sed -n 's/^需要在云厂商安全组放行[：:] *//p' | head -n 1)"
  [[ -n "$firewall" ]] || firewall="443/TCP, 443/UDP, ${PANEL_PORT}/TCP, 80/TCP"
  local prev_umask; prev_umask="$(umask)"
  umask 077
  # The password is NOT persisted here (shown once on screen); install-result.json
  # carries it only for the online installer, which reads and deletes it.
  # mktemp (O_EXCL) + rename: the web user owns this directory and could plant symlinks.
  env_tmp="$(mktemp "${RESULT_FILE}.XXXXXX")"
  {
    printf 'IVPN_ACCESS_URL=%q\n' "$url"
    printf 'IVPN_USERNAME=%q\n' "$ADMIN_USER"
    printf 'IVPN_PANEL_PORT=%q\n' "$PANEL_PORT"
    printf 'IVPN_LOGIN_PATH=%q\n' "$LOGIN_PATH"
  } > "$env_tmp"
  chmod 600 "$env_tmp"
  mv -Tf "$env_tmp" "$RESULT_FILE"

  if [[ "${IVPN_ONLINE_INSTALL:-0}" == "1" ]]; then
    json_tmp="$(mktemp "${RESULT_JSON}.XXXXXX")"
    jq -n --arg url "$url" --arg username "$ADMIN_USER" --arg password "$ADMIN_PASS" --arg firewall "$firewall" \
      '{version:1,panel_url:$url,admin_user:$username,admin_password:$password,
        password_reused:false,firewall:$firewall}' > "$json_tmp"
    chmod 600 "$json_tmp"
    mv -Tf "$json_tmp" "$RESULT_JSON"
  else
    rm -f "$RESULT_JSON"
  fi
  umask "$prev_umask"
}

print_result(){
  [[ "$LE_ACTIVE" == "1" ]] || die "可信 HTTPS 证书未激活，不能显示安装完成。"
  if [[ "${IVPN_ONLINE_INSTALL:-0}" == "1" ]]; then
    echo "安装完成，管理信息请在安装页面领取。"
    return
  fi
  local url; url="$(panel_url)"
  echo ""
  if command -v qrencode >/dev/null 2>&1; then
    qrencode -t utf8 -m 2 "$url" 2>/dev/null || true
  fi
  echo_line
  echo -e "${GREEN}安装完成${NC}"
  echo_line
  echo -e "访问地址：${YELLOW}${url}${NC}   ← 手机可以直接扫上面的二维码"
  echo "管理账号：${ADMIN_USER}"
  if [[ -n "$ADMIN_PASS" ]]; then
    echo -e "管理密码：${YELLOW}${ADMIN_PASS}${NC}"
  else
    echo "管理密码：没有改变，继续使用原来的密码"
  fi
  echo ""
  cd "$APP_DIR" && $IVPN info 2>/dev/null | grep -E '需要在云厂商|已启用连接' || true
  echo ""
  [[ -n "$ADMIN_PASS" ]] \
    && echo -e "${YELLOW}管理密码只显示这一次，不会保存在服务器上，请现在记下来。${NC}"
  echo -e "${YELLOW}访问地址已存在 ${RESULT_FILE}（只有 root 能读）；忘记密码用 renrenvpn reset-password。${NC}"
  echo_line
  echo "常用命令："
  echo "  renrenvpn info              查看访问地址和需要放行的端口"
  echo "  renrenvpn reset-password    忘记密码时重置"
  echo "  renrenvpn reset-path        更换管理页面地址"
  echo "  renrenvpn repair            连不上时重建配置并重启"
  echo "  renrenvpn backup            备份用户和设置"
  echo "  renrenvpn update            从已设置的 GitHub Release 安全更新"
  echo_line
}

# Sourcing exposes functions for tests without running the installer.
main(){
  check_root
  validate_repo
  init_private_tmp
  echo_line
  echo -e "${GREEN}人人VPN 管理面板安装脚本${NC}"
  echo_line
  install_dependencies
  check_dependencies_ready
  cleanup_old_install
  download_project
  install_python_env
  install_singbox_core
  snapshot_install
  activate_release
  activate_singbox_core
  resolve_identity
  create_services
  install_cli
  snapshot_firewall_rules
  prepare_vpn
  enable_bbr
  tune_udp_buffers
  setup_letsencrypt
  start_services
  verify_services
  verify_panel_https
  rotate_install_password
  write_install_result
  ROLLBACK_ARMED="0"
  print_result
}

# Avoid a failing top-level condition when this script is sourced under set -e.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  main "$@"
fi
