#!/bin/bash
set -e
set -o pipefail

CONFIG_FILE="${1:-}"
SERVER_STATE_DIR="$(dirname "${CONFIG_FILE:-/root/.ssl-renewal/missing.conf}")"
if [ -e "$SERVER_STATE_DIR/server.uninstalling" ] || [ -e "$SERVER_STATE_DIR/server.uninstalled" ]; then
    echo "SSL-Renewal 已卸载或正在卸载，跳过任务。"
    exit 0
fi

if [ -z "$CONFIG_FILE" ] || [ ! -r "$CONFIG_FILE" ]; then
    echo "❌ 动态 IP 配置文件不存在或不可读：$CONFIG_FILE"
    exit 1
fi

# shellcheck disable=SC1090
. "$CONFIG_FILE"

ACME_BIN="${ACME_BIN:-/root/.acme.sh/acme.sh}"
IP_VERSION="${IP_VERSION:-4}"
CHALLENGE_MODE="${CHALLENGE_MODE:-standalone}"
WEBROOT_PATH="${WEBROOT_PATH:-}"
RELOAD_CMD="${RELOAD_CMD:-}"
CERT_PATH="${CERT_PATH:-/root/dynamic-ip-v${IP_VERSION}.crt}"
KEY_PATH="${KEY_PATH:-/root/dynamic-ip-v${IP_VERSION}.key}"
STATE_FILE="${STATE_FILE:-/root/.ssl-renewal/dynamic-ip-v${IP_VERSION}.state}"
LOCK_BASE="${LOCK_BASE:-/run}"

log() {
    printf '%s [dynamic-ip-v%s] %s\n' "$(date '+%F %T')" "$IP_VERSION" "$*"
}

if [ "$IP_VERSION" != "4" ] && [ "$IP_VERSION" != "6" ]; then
    log "❌ IP_VERSION 只能是 4 或 6。"
    exit 1
fi

if [ ! -x "$ACME_BIN" ]; then
    log "❌ 未找到 acme.sh：$ACME_BIN"
    exit 1
fi

mkdir -p "$LOCK_BASE"
LOCK_DIR="$LOCK_BASE/ssl-renewal-dynamic-ip-v${IP_VERSION}.lock"
LOCK_PID_FILE="$LOCK_DIR/pid"

acquire_lock() {
    if mkdir "$LOCK_DIR" 2>/dev/null; then
        printf '%s\n' "$$" > "$LOCK_PID_FILE"
        return 0
    fi

    local old_pid=""
    if [ -r "$LOCK_PID_FILE" ]; then
        old_pid="$(tr -dc '0-9' < "$LOCK_PID_FILE")"
    fi

    if [ -n "$old_pid" ] && kill -0 "$old_pid" 2>/dev/null; then
        log "ℹ️ 已有同类型检查任务正在运行（PID $old_pid），本次跳过。"
        return 1
    fi

    log "⚠️ 检测到残留锁，正在自动恢复。"
    rm -rf "$LOCK_DIR"

    if ! mkdir "$LOCK_DIR" 2>/dev/null; then
        log "❌ 无法创建任务锁：$LOCK_DIR"
        return 1
    fi

    printf '%s\n' "$$" > "$LOCK_PID_FILE"
    return 0
}

if ! acquire_lock; then
    exit 0
fi

cleanup_lock() {
    rm -rf "$LOCK_DIR" >/dev/null 2>&1 || true
}

trap cleanup_lock EXIT
trap 'exit 130' INT TERM
if [ -e "$SERVER_STATE_DIR/server.uninstalling" ] || [ -e "$SERVER_STATE_DIR/server.uninstalled" ]; then exit 0; fi

normalize_public_ip() {
    python3 - "$1" "$2" <<'PY'
import ipaddress
import sys

raw = sys.argv[1].strip()
family = int(sys.argv[2])

try:
    ip = ipaddress.ip_address(raw)
except ValueError:
    sys.exit(1)

if ip.version != family or not ip.is_global:
    sys.exit(1)

print(ip.compressed)
PY
}

detect_public_ip() {
    local family="$1"
    local curl_flag
    local urls=()

    if [ "$family" = "4" ]; then
        curl_flag="-4"
        urls=(
            "https://4.ipw.cn"
            "https://api4.ipify.org"
            "https://ipv4.icanhazip.com"
        )
    else
        curl_flag="-6"
        urls=(
            "https://6.ipw.cn"
            "https://api6.ipify.org"
            "https://ipv6.icanhazip.com"
        )
    fi

    local url candidate normalized
    for url in "${urls[@]}"; do
        candidate="$(curl "$curl_flag" -fsS --connect-timeout 5 --max-time 8 "$url" 2>/dev/null | tr -d '\r\n[:space:]' || true)"
        [ -n "$candidate" ] || continue

        if normalized="$(normalize_public_ip "$candidate" "$family" 2>/dev/null)"; then
            printf '%s\n' "$normalized"
            return 0
        fi
    done

    return 1
}

check_port_free() {
    local port="$1"

    if command -v ss >/dev/null 2>&1; then
        if ss -ltnH 2>/dev/null | awk '{print $4}' | grep -Eq ":${port}$"; then
            log "❌ TCP ${port} 当前已被占用，无法使用 standalone 验证。"
            ss -ltnp 2>/dev/null | grep -E ":${port}[[:space:]]" || true
            return 1
        fi
    fi

    return 0
}

CURRENT_IP="$(detect_public_ip "$IP_VERSION" || true)"
if [ -z "$CURRENT_IP" ]; then
    log "❌ 无法检测到公网 IPv${IP_VERSION} 地址。请检查当前网络是否具备公网 IPv${IP_VERSION} 出口。"
    exit 1
fi

OLD_IP=""
if [ -f "$STATE_FILE" ]; then
    OLD_IP="$(tr -d '\r\n[:space:]' < "$STATE_FILE")"
fi

if [ "$CURRENT_IP" = "$OLD_IP" ] && [ -s "$CERT_PATH" ] && [ -s "$KEY_PATH" ]; then
    log "✅ 公网 IP 未变化：$CURRENT_IP"
    exit 0
fi

if [ -n "$OLD_IP" ] && [ "$CURRENT_IP" != "$OLD_IP" ]; then
    log "🔄 检测到公网 IP 变化：$OLD_IP -> $CURRENT_IP"
else
    log "🆕 当前公网 IPv${IP_VERSION}：$CURRENT_IP，准备签发证书。"
fi

ISSUE_ARGS=(--issue -d "$CURRENT_IP" --server letsencrypt --cert-profile shortlived --days 3)

case "$CHALLENGE_MODE" in
    standalone)
        check_port_free 80
        ISSUE_ARGS+=(--standalone)
        if [ "$IP_VERSION" = "4" ]; then
            ISSUE_ARGS+=(--listen-v4)
        else
            ISSUE_ARGS+=(--listen-v6)
        fi
        ;;
    webroot)
        if [ -z "$WEBROOT_PATH" ] || [ ! -d "$WEBROOT_PATH" ]; then
            log "❌ webroot 目录不存在：$WEBROOT_PATH"
            exit 1
        fi
        if [ ! -w "$WEBROOT_PATH" ]; then
            log "❌ webroot 目录不可写：$WEBROOT_PATH"
            exit 1
        fi
        ISSUE_ARGS+=(-w "$WEBROOT_PATH")
        ;;
    alpn)
        check_port_free 443
        ISSUE_ARGS+=(--alpn)
        if [ "$IP_VERSION" = "4" ]; then
            ISSUE_ARGS+=(--listen-v4)
        else
            ISSUE_ARGS+=(--listen-v6)
        fi
        ;;
    *)
        log "❌ 未知验证方式：$CHALLENGE_MODE"
        exit 1
        ;;
esac

log "🚀 正在为新 IP 申请 Let's Encrypt shortlived 证书..."
if ! "$ACME_BIN" "${ISSUE_ARGS[@]}"; then
    log "❌ 新 IP 证书申请失败。旧证书和旧 IP 状态保持不变。"
    exit 1
fi

INSTALL_ARGS=(
    --install-cert
    -d "$CURRENT_IP"
    --key-file "$KEY_PATH"
    --fullchain-file "$CERT_PATH"
)

if [ -n "$RELOAD_CMD" ]; then
    INSTALL_ARGS+=(--reloadcmd "$RELOAD_CMD")
fi

log "📂 正在覆盖稳定证书路径..."
if ! "$ACME_BIN" "${INSTALL_ARGS[@]}"; then
    log "❌ 新证书已签发，但安装到稳定路径失败。状态文件不会更新。"
    exit 1
fi

STATE_TMP="${STATE_FILE}.tmp.$$"
printf '%s\n' "$CURRENT_IP" > "$STATE_TMP"
chmod 600 "$STATE_TMP"
mv -f "$STATE_TMP" "$STATE_FILE"

if [ -n "$OLD_IP" ] && [ "$OLD_IP" != "$CURRENT_IP" ]; then
    "$ACME_BIN" --remove -d "$OLD_IP" >/dev/null 2>&1 || true
fi

log "✅ 动态 IP SSL 已更新完成。"
log "🌐 当前 IP：$CURRENT_IP"
log "📄 证书：$CERT_PATH"
log "🔐 私钥：$KEY_PATH"
