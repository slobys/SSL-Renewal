#!/bin/bash
set -e
set -o pipefail

BASE_DIR="${SSL_RENEWAL_REMOTE_BASE:-/root/.ssl-renewal/remote}"
DEVICE_DIR="$BASE_DIR/devices"
CERT_DIR="$BASE_DIR/certs"
LOG_DIR="$BASE_DIR/logs"
RUNNER="${SSL_RENEWAL_REMOTE_RUNNER:-$BASE_DIR/remote_ip_ssl.sh}"
ACME_BIN="${SSL_RENEWAL_ACME_BIN:-/root/.acme.sh/acme.sh}"
SSH_KEY="${SSL_RENEWAL_SSH_KEY:-/root/.ssh/id_ed25519}"
SERVER_STATE_DIR="$(dirname "$BASE_DIR")"
if [ -e "$SERVER_STATE_DIR/server.uninstalling" ] || [ -e "$SERVER_STATE_DIR/server.uninstalled" ]; then
    echo "SSL-Renewal 已卸载或正在卸载，跳过远程任务。"
    exit 0
fi

mkdir -p "$DEVICE_DIR" "$CERT_DIR" "$LOG_DIR"
chmod 700 "$BASE_DIR" "$DEVICE_DIR" "$CERT_DIR" "$LOG_DIR"

log() {
    printf '%s [remote-ip-ssl] %s\n' "$(date '+%F %T')" "$*"
}

die() {
    log "❌ $*"
    exit 1
}

sq() {
    local value="$1"
    value=${value//\'/\'\\\'\'}
    printf "'%s'" "$value"
}

sanitize_id() {
    printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9_.-]/-/g; s/--*/-/g; s/^-//; s/-$//'
}

validate_public_ip() {
    python3 - "$1" "${2:-}" <<'PY'
import ipaddress
import sys

raw = sys.argv[1].strip()
family = sys.argv[2].strip()

try:
    ip = ipaddress.ip_address(raw)
except ValueError:
    sys.exit(1)

if not ip.is_global:
    sys.exit(2)

if family and ip.version != int(family):
    sys.exit(3)

print(ip.compressed)
PY
}

device_file() {
    printf '%s/%s.conf\n' "$DEVICE_DIR" "$1"
}

state_file() {
    printf '%s/%s.state\n' "$DEVICE_DIR" "$1"
}

device_cert_dir() {
    printf '%s/%s\n' "$CERT_DIR" "$1"
}

write_var() {
    local name="$1"
    local value="$2"
    printf '%s=%q\n' "$name" "$value"
}

save_device_config() {
    local file="$1"
    local tmp="${file}.tmp.$$"

    {
        write_var DEVICE_ID "$DEVICE_ID"
        write_var DEVICE_NAME "$DEVICE_NAME"
        write_var SSH_HOST "$SSH_HOST"
        write_var SSH_PORT "$SSH_PORT"
        write_var SSH_USER "$SSH_USER"
        write_var ACME_EMAIL "$ACME_EMAIL"
        write_var IP_MODE "$IP_MODE"
        write_var IP_FAMILY "$IP_FAMILY"
        write_var FIXED_IP "$FIXED_IP"
        write_var REMOTE_CERT_PATH "$REMOTE_CERT_PATH"
        write_var REMOTE_KEY_PATH "$REMOTE_KEY_PATH"
        write_var RELOAD_CMD "$RELOAD_CMD"
        write_var REMOTE_FORWARD_PORT "$REMOTE_FORWARD_PORT"
        write_var LOCAL_HTTP_PORT "$LOCAL_HTTP_PORT"
        write_var DEVICE_TYPE "$DEVICE_TYPE"
        write_var CREATED_AT "$CREATED_AT"
    } > "$tmp"

    chmod 600 "$tmp"
    mv -f "$tmp" "$file"
}

load_device() {
    local id="$1"
    local file
    file="$(device_file "$id")"
    [ -f "$file" ] || die "远程设备不存在：$id"

    DEVICE_ID=""
    DEVICE_NAME=""
    SSH_HOST=""
    SSH_PORT="22"
    SSH_USER="root"
    ACME_EMAIL=""
    IP_MODE="unconfigured"
    IP_FAMILY="4"
    FIXED_IP=""
    REMOTE_CERT_PATH=""
    REMOTE_KEY_PATH=""
    RELOAD_CMD=""
    REMOTE_FORWARD_PORT="18080"
    LOCAL_HTTP_PORT="51080"
    DEVICE_TYPE="unknown"
    CREATED_AT=""

    # shellcheck disable=SC1090
    . "$file"
    DEVICE_CONFIG_FILE="$file"
    DEVICE_STATE_FILE="$(state_file "$DEVICE_ID")"
    DEVICE_CERT_DIR="$(device_cert_dir "$DEVICE_ID")"
    LOCAL_CERT_PATH="$DEVICE_CERT_DIR/fullchain.crt"
    LOCAL_KEY_PATH="$DEVICE_CERT_DIR/private.key"
}

load_state() {
    MANAGED_IP=""
    LAST_SUCCESS=""
    LAST_ERROR=""
    LAST_CHECK=""
    LAST_RENEW_CHECK="0"

    if [ -f "$DEVICE_STATE_FILE" ]; then
        # shellcheck disable=SC1090
        . "$DEVICE_STATE_FILE"
    fi
}

save_state() {
    local tmp="${DEVICE_STATE_FILE}.tmp.$$"

    {
        write_var MANAGED_IP "$MANAGED_IP"
        write_var LAST_SUCCESS "$LAST_SUCCESS"
        write_var LAST_ERROR "$LAST_ERROR"
        write_var LAST_CHECK "$LAST_CHECK"
        write_var LAST_RENEW_CHECK "$LAST_RENEW_CHECK"
    } > "$tmp"

    chmod 600 "$tmp"
    mv -f "$tmp" "$DEVICE_STATE_FILE"
}

ssh_target() {
    printf '%s@%s\n' "$SSH_USER" "$SSH_HOST"
}

ssh_base_args() {
    SSH_ARGS=(
        -i "$SSH_KEY"
        -p "$SSH_PORT"
        -o BatchMode=yes
        -o ConnectTimeout=8
        -o ServerAliveInterval=15
        -o ServerAliveCountMax=2
        -o StrictHostKeyChecking=accept-new
    )
}

remote_exec() {
    local command="$1"
    ssh_base_args
    ssh "${SSH_ARGS[@]}" "$(ssh_target)" "$command"
}

remote_exec_script() {
    local script="$1"
    ssh_base_args
    printf '%s\n' "$script" | ssh "${SSH_ARGS[@]}" "$(ssh_target)" "sh -s"
}

ensure_local_ssh_key() {
    mkdir -p /root/.ssh
    chmod 700 /root/.ssh

    if [ ! -f "$SSH_KEY" ]; then
        echo "🔑 未检测到 SSH 密钥，正在生成 $SSH_KEY ..."
        ssh-keygen -q -t ed25519 -N "" -f "$SSH_KEY"
    fi
}

test_ssh() {
    remote_exec "printf 'SSL_RENEWAL_SSH_OK\n'" 2>/dev/null | grep -q '^SSL_RENEWAL_SSH_OK$'
}

offer_copy_ssh_key() {
    ensure_local_ssh_key

    if test_ssh; then
        return 0
    fi

    echo
    echo "⚠️ 当前还不能免密 SSH 登录：$(ssh_target)"
    echo "远程自动续期必须使用 SSH 密钥，不能依赖人工输入密码。"
    read -r -p "是否现在使用 ssh-copy-id 安装公钥？（y/N）： " answer

    case "$answer" in
        y|Y)
            command -v ssh-copy-id >/dev/null 2>&1 || die "系统没有 ssh-copy-id，请先安装 openssh-client。"
            ssh-copy-id -i "${SSH_KEY}.pub" -p "$SSH_PORT" "$(ssh_target)"
            ;;
        *)
            die "未配置 SSH 免密登录，无法添加远程自动管理设备。"
            ;;
    esac

    test_ssh || die "SSH 公钥安装后仍无法免密登录，请检查目标地址、端口和 SSH 配置。"
}

detect_remote_type() {
    if remote_exec "test -f /etc/openwrt_release" >/dev/null 2>&1; then
        DEVICE_TYPE="openwrt"
        return 0
    fi

    DEVICE_TYPE="$(remote_exec "uname -s 2>/dev/null || echo unknown" | tr -d '\r\n[:space:]' | tr '[:upper:]' '[:lower:]')"
    [ -n "$DEVICE_TYPE" ] || DEVICE_TYPE="unknown"
}

remote_detect_public_ip() {
    local family="$1"
    local command

    command="$(cat <<EOF
set -e
family=$(sq "$family")
fetch() {
    url="\$1"
    if command -v curl >/dev/null 2>&1; then
        if [ "\$family" = "4" ]; then
            curl -4 -fsS --connect-timeout 5 --max-time 8 "\$url" 2>/dev/null
        else
            curl -6 -fsS --connect-timeout 5 --max-time 8 "\$url" 2>/dev/null
        fi
        return
    fi
    if command -v wget >/dev/null 2>&1; then
        wget -qO- -T 8 "\$url" 2>/dev/null
        return
    fi
    return 1
}
if [ "\$family" = "4" ]; then
    urls="http://4.ipw.cn http://api4.ipify.org http://ipv4.icanhazip.com"
else
    urls="http://6.ipw.cn http://api6.ipify.org http://ipv6.icanhazip.com"
fi
for url in \$urls; do
    value="\$(fetch "\$url" 2>/dev/null | tr -d '\\r\\n \\t' || true)"
    if [ -n "\$value" ]; then
        printf '%s\\n' "\$value"
        exit 0
    fi
done
exit 1
EOF
)"

    local raw normalized
    raw="$(remote_exec "$command" 2>/dev/null | head -n 1 | tr -d '\r\n[:space:]' || true)"
    [ -n "$raw" ] || return 1

    set +e
    normalized="$(validate_public_ip "$raw" "$family" 2>/dev/null)"
    local rc=$?
    set -e

    [ "$rc" -eq 0 ] || return 1
    printf '%s\n' "$normalized"
}

ensure_openwrt_gateway_ports() {
    [ "$DEVICE_TYPE" = "openwrt" ] || return 0

    local current
    current="$(remote_exec "uci -q get dropbear.@dropbear[0].GatewayPorts 2>/dev/null || echo 0" 2>/dev/null | tr -d '\r\n[:space:]' || true)"
    if [ "$current" = "1" ]; then
        return 0
    fi

    echo "🔧 正在为 OpenWrt 启用 Dropbear GatewayPorts（远程 ACME 验证需要）..."
    remote_exec "uci set dropbear.@dropbear[0].GatewayPorts='1'; uci commit dropbear; (/etc/init.d/dropbear restart >/dev/null 2>&1 &) " >/dev/null 2>&1 || true
    sleep 2

    test_ssh || die "启用 Dropbear GatewayPorts 后 SSH 未恢复，请到 OpenWrt 检查 /etc/config/dropbear。"
}

remote_preflight() {
    echo "🔍 正在检查远程设备..."

    test_ssh || die "SSH 免密连接失败：$(ssh_target)"
    ensure_openwrt_gateway_ports

    local info
    info="$(remote_exec "printf 'kernel='; uname -s; printf 'arch='; uname -m; if [ -f /etc/openwrt_release ]; then echo openwrt=yes; else echo openwrt=no; fi; command -v nft >/dev/null 2>&1 && echo nft=yes || true; command -v iptables >/dev/null 2>&1 && echo iptables=yes || true; command -v ip6tables >/dev/null 2>&1 && echo ip6tables=yes || true" 2>/dev/null || true)"
    printf '%s\n' "$info"

    if [ "$DEVICE_TYPE" = "openwrt" ]; then
        if [ "$IP_FAMILY" = "6" ]; then
            printf '%s\n' "$info" | grep -Eq '^(nft|ip6tables)=yes$' ||
                die "OpenWrt 上未检测到 nft 或 ip6tables，无法建立 IPv6 ACME 端口重定向。"
        else
            printf '%s\n' "$info" | grep -Eq '^(nft|iptables)=yes$' ||
                die "OpenWrt 上未检测到 nft 或 iptables，无法建立 IPv4 ACME 端口重定向。"
        fi
    else
        echo "⚠️ 当前远程自动验证主要针对 OpenWrt 测试；其他 Linux 设备会尝试兼容，但不保证防火墙链结构一致。"
    fi
}

derive_ports() {
    local id="$1"
    local n
    n="$(printf '%s' "$id" | cksum | awk '{print $1}')"
    REMOTE_FORWARD_PORT="$((18000 + n % 1000))"
    LOCAL_HTTP_PORT="$((51000 + n % 1000))"
}

remote_firewall_add() {
    local tag="sslrenewal-${DEVICE_ID}"
    local rport="$REMOTE_FORWARD_PORT"
    local family="$IP_FAMILY"

    local script
    script="$(cat <<EOF
set -e
tag=$(sq "$tag")
rport=$(sq "$rport")
family=$(sq "$family")

cleanup_nft() {
    for chain in dstnat input; do
        nft -a list chain inet fw4 "\$chain" 2>/dev/null |
        sed -n "/comment \"\$tag-/s/.* handle \\([0-9][0-9]*\\).*/\\1/p" |
        while read -r handle; do
            [ -n "\$handle" ] && nft delete rule inet fw4 "\$chain" handle "\$handle" 2>/dev/null || true
        done
    done
}

if command -v nft >/dev/null 2>&1 && nft list table inet fw4 >/dev/null 2>&1; then
    cleanup_nft
    nft insert rule inet fw4 dstnat tcp dport 80 redirect to :"\$rport" comment "\$tag-nat"
    nft insert rule inet fw4 input tcp dport "\$rport" accept comment "\$tag-input"
    echo nft
    exit 0
fi

if [ "\$family" = "6" ] && command -v ip6tables >/dev/null 2>&1; then
    ip6tables -t nat -I PREROUTING 1 -p tcp --dport 80 -j REDIRECT --to-ports "\$rport"
    ip6tables -I INPUT 1 -p tcp --dport "\$rport" -j ACCEPT
    echo ip6tables
    exit 0
fi

if [ "\$family" = "4" ] && command -v iptables >/dev/null 2>&1; then
    iptables -t nat -I PREROUTING 1 -p tcp --dport 80 -j REDIRECT --to-ports "\$rport"
    iptables -I INPUT 1 -p tcp --dport "\$rport" -j ACCEPT
    echo iptables
    exit 0
fi

exit 1
EOF
)"

    remote_exec_script "$script"
}

remote_firewall_remove() {
    local tag="sslrenewal-${DEVICE_ID}"
    local rport="$REMOTE_FORWARD_PORT"

    local script
    script="$(cat <<EOF
tag=$(sq "$tag")
rport=$(sq "$rport")
if command -v nft >/dev/null 2>&1 && nft list table inet fw4 >/dev/null 2>&1; then
    for chain in dstnat input; do
        nft -a list chain inet fw4 "\$chain" 2>/dev/null |
        sed -n "/comment \"\$tag-/s/.* handle \\([0-9][0-9]*\\).*/\\1/p" |
        while read -r handle; do
            [ -n "\$handle" ] && nft delete rule inet fw4 "\$chain" handle "\$handle" 2>/dev/null || true
        done
    done
fi
if command -v iptables >/dev/null 2>&1; then
    while iptables -t nat -C PREROUTING -p tcp --dport 80 -j REDIRECT --to-ports "\$rport" >/dev/null 2>&1; do
        iptables -t nat -D PREROUTING -p tcp --dport 80 -j REDIRECT --to-ports "\$rport" >/dev/null 2>&1 || break
    done
    while iptables -C INPUT -p tcp --dport "\$rport" -j ACCEPT >/dev/null 2>&1; do
        iptables -D INPUT -p tcp --dport "\$rport" -j ACCEPT >/dev/null 2>&1 || break
    done
fi
if command -v ip6tables >/dev/null 2>&1; then
    while ip6tables -t nat -C PREROUTING -p tcp --dport 80 -j REDIRECT --to-ports "\$rport" >/dev/null 2>&1; do
        ip6tables -t nat -D PREROUTING -p tcp --dport 80 -j REDIRECT --to-ports "\$rport" >/dev/null 2>&1 || break
    done
    while ip6tables -C INPUT -p tcp --dport "\$rport" -j ACCEPT >/dev/null 2>&1; do
        ip6tables -D INPUT -p tcp --dport "\$rport" -j ACCEPT >/dev/null 2>&1 || break
    done
fi
exit 0
EOF
)"

    remote_exec_script "$script" >/dev/null 2>&1 || true
}

TUNNEL_PID=""

start_reverse_tunnel() {
    ssh_base_args
    local bind_addr="0.0.0.0"
    [ "$IP_FAMILY" = "6" ] && bind_addr="[::]"

    ssh "${SSH_ARGS[@]}" \
        -o ExitOnForwardFailure=yes \
        -N -T \
        -R "${bind_addr}:${REMOTE_FORWARD_PORT}:127.0.0.1:${LOCAL_HTTP_PORT}" \
        "$(ssh_target)" &
    TUNNEL_PID=$!

    sleep 1
    if ! kill -0 "$TUNNEL_PID" 2>/dev/null; then
        wait "$TUNNEL_PID" 2>/dev/null || true
        TUNNEL_PID=""
        die "SSH 反向端口转发启动失败。请检查目标 SSH 服务是否允许 TCP forwarding。"
    fi

    if ! remote_exec "netstat -lnt 2>/dev/null | grep -E '[:.]$REMOTE_FORWARD_PORT[[:space:]]' >/dev/null || ss -lnt 2>/dev/null | grep -E ':$REMOTE_FORWARD_PORT[[:space:]]' >/dev/null" >/dev/null 2>&1; then
        stop_reverse_tunnel
        die "远端没有出现反向转发监听端口 $REMOTE_FORWARD_PORT。"
    fi
}

stop_reverse_tunnel() {
    if [ -n "${TUNNEL_PID:-}" ] && kill -0 "$TUNNEL_PID" 2>/dev/null; then
        kill "$TUNNEL_PID" >/dev/null 2>&1 || true
        wait "$TUNNEL_PID" 2>/dev/null || true
    fi
    TUNNEL_PID=""
}

cleanup_challenge_proxy() {
    remote_firewall_remove || true
    stop_reverse_tunnel || true
}

with_challenge_proxy_start() {
    remote_firewall_remove || true
    start_reverse_tunnel

    if ! remote_firewall_add >/dev/null; then
        stop_reverse_tunnel
        die "无法在远端建立 TCP 80 临时重定向。"
    fi
}

challenge_url() {
    local ip="$1"
    local path="$2"
    if [ "$IP_FAMILY" = "6" ]; then
        printf 'http://[%s]/%s\n' "$ip" "$path"
    else
        printf 'http://%s/%s\n' "$ip" "$path"
    fi
}

challenge_self_test() {
    local ip="$1"
    local tmpdir token path body server_pid=""
    tmpdir="$(mktemp -d)"
    token="sslrenewal-${DEVICE_ID}-$$"
    path=".well-known/acme-challenge/$token"
    body="SSL_RENEWAL_TEST_${DEVICE_ID}_$$"

    mkdir -p "$tmpdir/.well-known/acme-challenge"
    printf '%s' "$body" > "$tmpdir/$path"

    python3 -m http.server "$LOCAL_HTTP_PORT" --bind 127.0.0.1 --directory "$tmpdir" >/dev/null 2>&1 &
    server_pid=$!
    sleep 1

    if ! kill -0 "$server_pid" 2>/dev/null; then
        rm -rf "$tmpdir"
        die "本机测试 HTTP 服务无法监听 127.0.0.1:$LOCAL_HTTP_PORT。"
    fi

    local url result=""
    url="$(challenge_url "$ip" "$path")"

    set +e
    if [ "$IP_FAMILY" = "6" ]; then
        result="$(curl -g -6 -fsS --connect-timeout 8 --max-time 15 "$url" 2>/dev/null)"
    else
        result="$(curl -4 -fsS --connect-timeout 8 --max-time 15 "$url" 2>/dev/null)"
    fi
    local rc=$?
    set -e

    kill "$server_pid" >/dev/null 2>&1 || true
    wait "$server_pid" 2>/dev/null || true
    rm -rf "$tmpdir"

    if [ "$rc" -ne 0 ] || [ "$result" != "$body" ]; then
        echo "❌ 远程 HTTP-01 自检失败：$url"
        echo "请检查："
        echo "  1. 家庭公网 IP 是否真实可入站（不是 CGNAT）"
        echo "  2. 上级光猫/NAT 是否把 TCP 80 转发到 OpenWrt"
        echo "  3. 运营商是否封锁入站 TCP 80"
        echo "  4. OpenWrt 防火墙/SSH TCP forwarding 是否正常"
        return 1
    fi

    echo "✅ 远程 HTTP-01 自检通过：$url"
}

ensure_acme_account() {
    if [ ! -x "$ACME_BIN" ]; then
        [ -n "${ACME_EMAIL:-}" ] || die "未设置 ACME 邮箱，无法安装 acme.sh。"
        echo "📥 云服务器未安装 acme.sh，正在安装..."
        curl -fsSL https://get.acme.sh | sh -s email="$ACME_EMAIL"
    fi

    "$ACME_BIN" --upgrade >/dev/null 2>&1 || true
    "$ACME_BIN" --register-account -m "$ACME_EMAIL" --server letsencrypt >/dev/null 2>&1 || true
}

issue_new_ip_certificate() {
    local ip="$1"
    local force_flag="${2:-0}"
    local args=(
        --issue
        -d "$ip"
        --server letsencrypt
        --cert-profile shortlived
        --days 3
        --standalone
        --httpport "$LOCAL_HTTP_PORT"
        --listen-v4
    )

    if [ "$force_flag" = "1" ]; then
        args+=(--force)
    fi

    "$ACME_BIN" "${args[@]}"
}

renew_ip_certificate() {
    local ip="$1"
    local force_flag="${2:-0}"
    local args=(
        --renew
        -d "$ip"
        --server letsencrypt
        --httpport "$LOCAL_HTTP_PORT"
        --listen-v4
    )

    if [ "$force_flag" = "1" ]; then
        args+=(--force)
    fi

    "$ACME_BIN" "${args[@]}"
}

install_local_copy() {
    local ip="$1"
    mkdir -p "$DEVICE_CERT_DIR"
    chmod 700 "$DEVICE_CERT_DIR"

    "$ACME_BIN" --install-cert -d "$ip"         --key-file "$LOCAL_KEY_PATH"         --fullchain-file "$LOCAL_CERT_PATH"

    chmod 600 "$LOCAL_KEY_PATH"
    chmod 644 "$LOCAL_CERT_PATH"
}

remote_stage_file() {
    local local_file="$1"
    local remote_file="$2"
    local remote_tmp="${remote_file}.sslrenewal.new.$$"
    local parent
    parent="$(dirname "$remote_file")"

    remote_exec "mkdir -p $(sq "$parent") && cat > $(sq "$remote_tmp")" < "$local_file"
    printf '%s\n' "$remote_tmp"
}

deploy_certificate_remote() {
    local staged_cert staged_key
    staged_cert="$(remote_stage_file "$LOCAL_CERT_PATH" "$REMOTE_CERT_PATH")"
    staged_key="$(remote_stage_file "$LOCAL_KEY_PATH" "$REMOTE_KEY_PATH")"

    local script
    script="$(cat <<EOF
set -e
cert=$(sq "$REMOTE_CERT_PATH")
key=$(sq "$REMOTE_KEY_PATH")
newcert=$(sq "$staged_cert")
newkey=$(sq "$staged_key")
reload=$(sq "$RELOAD_CMD")
bakcert="\$cert.sslrenewal.bak"
bakkey="\$key.sslrenewal.bak"
hadcert=0
hadkey=0

[ -s "\$newcert" ] || exit 21
[ -s "\$newkey" ] || exit 22

if [ -f "\$cert" ]; then
    cp -p "\$cert" "\$bakcert"
    hadcert=1
fi
if [ -f "\$key" ]; then
    cp -p "\$key" "\$bakkey"
    hadkey=1
fi

chmod 644 "\$newcert"
chmod 600 "\$newkey"
mv -f "\$newcert" "\$cert"
mv -f "\$newkey" "\$key"

if [ -n "\$reload" ]; then
    if ! sh -c "\$reload"; then
        [ "\$hadcert" = "1" ] && mv -f "\$bakcert" "\$cert" || rm -f "\$cert"
        [ "\$hadkey" = "1" ] && mv -f "\$bakkey" "\$key" || rm -f "\$key"
        sh -c "\$reload" >/dev/null 2>&1 || true
        exit 23
    fi
fi

rm -f "\$bakcert" "\$bakkey"
exit 0
EOF
)"

    if ! remote_exec_script "$script"; then
        remote_exec "rm -f $(sq "$staged_cert") $(sq "$staged_key")" >/dev/null 2>&1 || true
        return 1
    fi

    return 0
}

remove_old_acme_entry() {
    local old_ip="$1"
    local new_ip="$2"
    if [ -n "$old_ip" ] && [ "$old_ip" != "$new_ip" ]; then
        "$ACME_BIN" --remove -d "$old_ip" >/dev/null 2>&1 || true
    fi
}

certificate_expiry() {
    if [ -s "$LOCAL_CERT_PATH" ] && command -v openssl >/dev/null 2>&1; then
        openssl x509 -in "$LOCAL_CERT_PATH" -noout -enddate 2>/dev/null | cut -d= -f2-
    fi
}

setup_and_test_proxy() {
    local ip="$1"

    ensure_openwrt_gateway_ports
    echo "🔗 正在建立临时 ACME 验证链路..."
    with_challenge_proxy_start

    if ! challenge_self_test "$ip"; then
        cleanup_challenge_proxy
        return 1
    fi

    return 0
}

perform_issue_or_renew() {
    local ip="$1"
    local operation="$2"
    local force_flag="${3:-0}"
    local old_ip="${MANAGED_IP:-}"

    ensure_acme_account
    setup_and_test_proxy "$ip" || return 1
    trap cleanup_challenge_proxy EXIT
    trap 'cleanup_challenge_proxy; exit 130' INT TERM

    local rc=0
    echo "🔐 正在通过家庭公网 IP $ip 完成 Let's Encrypt 验证..."

    if [ "$operation" = "new" ]; then
        if issue_new_ip_certificate "$ip" "$force_flag"; then
            rc=0
        else
            rc=$?
        fi
    else
        if renew_ip_certificate "$ip" "$force_flag"; then
            rc=0
        else
            rc=$?
        fi
    fi

    cleanup_challenge_proxy
    trap - EXIT INT TERM

    if [ "$rc" -eq 2 ] && [ "$operation" = "renew" ]; then
        echo "ℹ️ 证书尚未进入续期窗口，本次无需更新。"
        return 2
    fi

    if [ "$rc" -eq 2 ] && [ "$operation" = "new" ]; then
        echo "ℹ️ acme.sh 已存在该 IP 的有效证书，尝试复用现有证书继续部署。"
        rc=0
    fi

    if [ "$rc" -ne 0 ]; then
        return "$rc"
    fi

    install_local_copy "$ip"

    if ! deploy_certificate_remote; then
        echo "❌ 证书已在云服务器签发，但部署到远端失败；远端旧证书已尽量保留/回滚。"
        return 30
    fi

    MANAGED_IP="$ip"
    LAST_SUCCESS="$(date '+%F %T')"
    LAST_ERROR=""
    LAST_CHECK="$(date '+%F %T')"
    LAST_RENEW_CHECK="$(date +%s)"
    save_state

    remove_old_acme_entry "$old_ip" "$ip"

    echo "✅ 远程 IP SSL 更新完成：$ip"
    echo "📤 已部署：$REMOTE_CERT_PATH"
    echo "🔐 私钥：$REMOTE_KEY_PATH"
    return 0
}

install_device_cron() {
    local id="$1"
    local mode="$2"
    local logfile="$LOG_DIR/${id}.log"
    local schedule

    if [ "$mode" = "dynamic" ]; then
        schedule="*/5 * * * *"
    else
        schedule="17 */6 * * *"
    fi

    (
        crontab -l 2>/dev/null | grep -Fv "$RUNNER cron $id" || true
        echo "$schedule $RUNNER cron $id >> $logfile 2>&1"
    ) | crontab -
}

remove_device_cron() {
    local id="$1"
    (
        crontab -l 2>/dev/null | grep -Fv "$RUNNER cron $id" || true
    ) | crontab -
}

choose_device() {
    local files=()
    local f id name index=1

    while IFS= read -r f; do
        files+=("$f")
    done < <(find "$DEVICE_DIR" -maxdepth 1 -type f -name '*.conf' | sort)

    [ "${#files[@]}" -gt 0 ] || die "还没有添加远程设备。"

    echo
    echo "请选择远程设备："
    for f in "${files[@]}"; do
        id="$(basename "$f" .conf)"
        name="$id"
        # shellcheck disable=SC1090
        . "$f"
        printf '%d）%s [%s] %s@%s:%s\n' "$index" "${DEVICE_NAME:-$id}" "$id" "${SSH_USER:-root}" "${SSH_HOST:-?}" "${SSH_PORT:-22}"
        index=$((index + 1))
    done

    read -r -p "输入序号： " selection
    [[ "$selection" =~ ^[0-9]+$ ]] || die "无效序号。"
    [ "$selection" -ge 1 ] && [ "$selection" -le "${#files[@]}" ] || die "无效序号。"

    SELECTED_DEVICE_ID="$(basename "${files[$((selection - 1))]}" .conf)"
}

add_remote_device() {
    echo
    echo "============== 添加远程设备 =============="
    read -r -p "设备名称（例如 Home-OpenWrt）： " DEVICE_NAME
    [ -n "$DEVICE_NAME" ] || die "设备名称不能为空。"

    local default_id
    default_id="$(sanitize_id "$DEVICE_NAME")"
    [ -n "$default_id" ] || default_id="remote-$(date +%s)"

    read -r -p "设备ID [$default_id]： " DEVICE_ID
    DEVICE_ID="${DEVICE_ID:-$default_id}"
    DEVICE_ID="$(sanitize_id "$DEVICE_ID")"
    [ -n "$DEVICE_ID" ] || die "设备 ID 无效。"

    local file
    file="$(device_file "$DEVICE_ID")"
    [ ! -e "$file" ] || die "设备 ID 已存在：$DEVICE_ID"

    read -r -p "SSH管理地址（推荐填 ZeroTier IP）： " SSH_HOST
    [ -n "$SSH_HOST" ] || die "SSH 管理地址不能为空。"

    read -r -p "SSH端口 [22]： " SSH_PORT
    SSH_PORT="${SSH_PORT:-22}"
    [[ "$SSH_PORT" =~ ^[0-9]+$ ]] || die "SSH 端口无效。"

    read -r -p "SSH用户 [root]： " SSH_USER
    SSH_USER="${SSH_USER:-root}"

    read -r -p "Let's Encrypt账户邮箱： " ACME_EMAIL
    [[ "$ACME_EMAIL" =~ ^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$ ]] || die "电子邮件地址格式不正确。"

    IP_MODE="unconfigured"
    IP_FAMILY="4"
    FIXED_IP=""
    DEVICE_TYPE="unknown"
    CREATED_AT="$(date '+%F %T')"

    derive_ports "$DEVICE_ID"

    ensure_local_ssh_key
    offer_copy_ssh_key
    detect_remote_type
    remote_preflight

    local default_cert="/etc/ssl/ssl-renewal/${DEVICE_ID}.crt"
    local default_key="/etc/ssl/ssl-renewal/${DEVICE_ID}.key"
    local default_reload=""

    if [ "$DEVICE_TYPE" = "openwrt" ]; then
        default_cert="/etc/uhttpd.crt"
        default_key="/etc/uhttpd.key"
        default_reload="/etc/init.d/uhttpd restart"
    fi

    read -r -p "远端证书路径 [$default_cert]： " REMOTE_CERT_PATH
    REMOTE_CERT_PATH="${REMOTE_CERT_PATH:-$default_cert}"

    read -r -p "远端私钥路径 [$default_key]： " REMOTE_KEY_PATH
    REMOTE_KEY_PATH="${REMOTE_KEY_PATH:-$default_key}"

    if [ -n "$default_reload" ]; then
        read -r -p "证书更新后的重载命令 [$default_reload]： " RELOAD_CMD
        RELOAD_CMD="${RELOAD_CMD:-$default_reload}"
    else
        read -r -p "证书更新后的重载命令（可留空）： " RELOAD_CMD
    fi

    save_device_config "$file"
    DEVICE_STATE_FILE="$(state_file "$DEVICE_ID")"
    MANAGED_IP=""
    LAST_SUCCESS=""
    LAST_ERROR=""
    LAST_CHECK=""
    LAST_RENEW_CHECK="0"
    save_state

    echo
    echo "✅ 远程设备已添加：$DEVICE_NAME [$DEVICE_ID]"
    echo "🔗 管理链路：$(ssh_target)"
    echo "🧩 设备类型：$DEVICE_TYPE"
    echo "ℹ️ 下一步请选择“固定公网 IP”或“动态公网 IP”。"
}

configure_fixed_ip() {
    choose_device
    load_device "$SELECTED_DEVICE_ID"
    load_state

    read -r -p "请输入该设备对应的固定公网 IP： " input_ip

    set +e
    local normalized
    normalized="$(validate_public_ip "$input_ip" "" 2>/dev/null)"
    local rc=$?
    set -e
    [ "$rc" -eq 0 ] || die "不是可公开路由的公网 IP：$input_ip"

    if [[ "$normalized" == *:* ]]; then
        IP_FAMILY="6"
    else
        IP_FAMILY="4"
    fi

    IP_MODE="fixed"
    FIXED_IP="$normalized"
    save_device_config "$DEVICE_CONFIG_FILE"

    remote_preflight

    if perform_issue_or_renew "$FIXED_IP" "new" 0; then
        install_device_cron "$DEVICE_ID" "fixed"
        echo "✅ 固定公网 IP 模式已启用；每 6 小时检查一次续期。"
    else
        LAST_ERROR="首次固定 IP 证书签发失败：$(date '+%F %T')"
        LAST_CHECK="$(date '+%F %T')"
        save_state
        die "固定 IP 证书首次签发失败。"
    fi
}

configure_dynamic_ip() {
    choose_device
    load_device "$SELECTED_DEVICE_ID"
    load_state

    echo "请选择动态公网 IP 类型："
    echo "1）IPv4"
    echo "2）IPv6"
    read -r -p "输入选项（1-2）： " family_choice
    case "$family_choice" in
        1) IP_FAMILY="4" ;;
        2) IP_FAMILY="6" ;;
        *) die "无效选项。" ;;
    esac

    IP_MODE="dynamic"
    FIXED_IP=""
    save_device_config "$DEVICE_CONFIG_FILE"

    remote_preflight

    local current_ip
    current_ip="$(remote_detect_public_ip "$IP_FAMILY" || true)"
    [ -n "$current_ip" ] || die "无法从远端设备检测到公网 IPv$IP_FAMILY。"

    echo "✅ 远端当前公网 IPv$IP_FAMILY：$current_ip"

    if perform_issue_or_renew "$current_ip" "new" 0; then
        install_device_cron "$DEVICE_ID" "dynamic"
        echo "✅ 动态公网 IP 模式已启用；每 5 分钟检查 IP 变化。"
    else
        LAST_ERROR="首次动态 IP 证书签发失败：$(date '+%F %T')"
        LAST_CHECK="$(date '+%F %T')"
        save_state
        die "动态 IP 证书首次签发失败。"
    fi
}

process_device_check() {
    local id="$1"
    local force_flag="${2:-0}"
    load_device "$id"
    load_state

    [ "$IP_MODE" != "unconfigured" ] || {
        log "设备 $DEVICE_ID 尚未设置固定/动态公网 IP 模式。"
        return 0
    }

    if ! test_ssh; then
        LAST_ERROR="SSH连接失败：$(date '+%F %T')"
        LAST_CHECK="$(date '+%F %T')"
        save_state
        return 1
    fi

    local current_ip
    if [ "$IP_MODE" = "fixed" ]; then
        current_ip="$FIXED_IP"
    else
        current_ip="$(remote_detect_public_ip "$IP_FAMILY" || true)"
        if [ -z "$current_ip" ]; then
            LAST_ERROR="无法检测远端公网 IP：$(date '+%F %T')"
            LAST_CHECK="$(date '+%F %T')"
            save_state
            return 1
        fi
    fi

    LAST_CHECK="$(date '+%F %T')"

    if [ "$current_ip" != "${MANAGED_IP:-}" ]; then
        log "检测到目标 IP 变化：${MANAGED_IP:-<none>} -> $current_ip"
        if perform_issue_or_renew "$current_ip" "new" "$force_flag"; then
            return 0
        fi
        LAST_ERROR="IP变化后重签失败：$(date '+%F %T')"
        save_state
        return 1
    fi

    local now
    now="$(date +%s)"

    if [ "$force_flag" != "1" ]; then
        local last="${LAST_RENEW_CHECK:-0}"
        if [[ "$last" =~ ^[0-9]+$ ]] && [ "$((now - last))" -lt 21600 ]; then
            save_state
            log "IP 未变化，距离上次续期检查不足 6 小时，本次跳过。"
            return 0
        fi
    fi

    LAST_RENEW_CHECK="$now"
    save_state

    local rc=0
    if perform_issue_or_renew "$current_ip" "renew" "$force_flag"; then
        rc=0
    else
        rc=$?
    fi

    if [ "$rc" -eq 0 ] || [ "$rc" -eq 2 ]; then
        LAST_ERROR=""
        LAST_CHECK="$(date '+%F %T')"
        save_state
        return 0
    fi

    LAST_ERROR="证书续期失败：$(date '+%F %T')"
    save_state
    return "$rc"
}

manual_update() {
    choose_device
    load_device "$SELECTED_DEVICE_ID"

    echo
    echo "1）正常检查（推荐，未到续期时间会自动跳过）"
    echo "2）强制重新签发（会消耗 CA 请求额度）"
    read -r -p "输入选项（1-2）： " action

    case "$action" in
        1) process_device_check "$DEVICE_ID" 0 ;;
        2)
            read -r -p "确认强制重签？输入 YES 继续： " confirm
            [ "$confirm" = "YES" ] || return 0
            process_device_check "$DEVICE_ID" 1
            ;;
        *) die "无效选项。" ;;
    esac
}

show_device_status() {
    local id="$1"
    load_device "$id"
    load_state

    echo "----------------------------------------"
    echo "设备：$DEVICE_NAME [$DEVICE_ID]"
    echo "类型：$DEVICE_TYPE"
    echo "SSH：$SSH_USER@$SSH_HOST:$SSH_PORT"
    echo "ACME邮箱：$ACME_EMAIL"
    echo "模式：$IP_MODE"
    echo "IP类型：IPv$IP_FAMILY"
    [ "$IP_MODE" = "fixed" ] && echo "固定公网IP：$FIXED_IP"
    echo "当前管理IP：${MANAGED_IP:-未签发}"
    echo "远端证书：$REMOTE_CERT_PATH"
    echo "远端私钥：$REMOTE_KEY_PATH"
    echo "最后成功：${LAST_SUCCESS:-无}"
    echo "最后检查：${LAST_CHECK:-无}"
    echo "最后错误：${LAST_ERROR:-无}"

    local expiry
    expiry="$(certificate_expiry || true)"
    [ -n "$expiry" ] && echo "证书到期：$expiry"

    if crontab -l 2>/dev/null | grep -Fq "$RUNNER cron $DEVICE_ID"; then
        if [ "$IP_MODE" = "dynamic" ]; then
            echo "自动任务：已启用（每5分钟）"
        else
            echo "自动任务：已启用（每6小时）"
        fi
    else
        echo "自动任务：未启用"
    fi

    if test_ssh; then
        echo "SSH状态：✅ 可连接"
        if [ "$IP_MODE" = "dynamic" ]; then
            local observed
            observed="$(remote_detect_public_ip "$IP_FAMILY" || true)"
            [ -n "$observed" ] && echo "远端实时公网IP：$observed"
        fi
    else
        echo "SSH状态：❌ 不可连接"
    fi
}

view_status() {
    local found=0
    local f id

    for f in "$DEVICE_DIR"/*.conf; do
        [ -e "$f" ] || continue
        found=1
        id="$(basename "$f" .conf)"
        show_device_status "$id"
    done

    [ "$found" -eq 1 ] || echo "尚未添加远程设备。"
}

delete_device() {
    choose_device
    load_device "$SELECTED_DEVICE_ID"
    load_state

    echo "准备删除：$DEVICE_NAME [$DEVICE_ID]"
    echo "注意：远端已经部署的证书文件不会删除，避免导致现有服务中断。"
    read -r -p "输入 DELETE 确认： " confirm
    [ "$confirm" = "DELETE" ] || return 0

    remove_device_cron "$DEVICE_ID"

    if [ -n "${MANAGED_IP:-}" ]; then
        "$ACME_BIN" --remove -d "$MANAGED_IP" >/dev/null 2>&1 || true
    fi

    rm -f "$DEVICE_CONFIG_FILE" "$DEVICE_STATE_FILE"
    rm -rf "$DEVICE_CERT_DIR"
    rm -f "$LOG_DIR/${DEVICE_ID}.log"

    echo "✅ 已删除远程设备配置和自动任务。"
    echo "ℹ️ 远端证书/私钥保持原样。"
}

ensure_runner_installed() {
    if [ "$(readlink -f "$0" 2>/dev/null || printf '%s' "$0")" != "$RUNNER" ]; then
        install -m 700 "$0" "$RUNNER"
    else
        chmod 700 "$RUNNER"
    fi
}

remote_menu() {
    ensure_runner_installed
    ensure_local_ssh_key

    while true; do
        clear 2>/dev/null || true
        echo "============ 远程设备 IP 证书 ============"
        echo "本机负责申请，证书给远端设备使用；与本机动态 IP 配置相互独立。"
        echo "1）添加远程设备"
        echo "2）配置远端固定公网 IP"
        echo "3）配置远端动态公网 IP"
        echo "4）立即申请/更新证书"
        echo "5）查看设备状态"
        echo "6）删除设备"
        echo "0）返回主菜单"
        echo "=========================================="
        read -r -p "请输入选项（0-6）： " option || return 0

        case "$option" in
            1)
                add_remote_device
                read -r -p "按回车继续..." _
                ;;
            2)
                configure_fixed_ip
                read -r -p "按回车继续..." _
                ;;
            3)
                configure_dynamic_ip
                read -r -p "按回车继续..." _
                ;;
            4)
                manual_update
                read -r -p "按回车继续..." _
                ;;
            5)
                view_status
                read -r -p "按回车继续..." _
                ;;
            6)
                delete_device
                read -r -p "按回车继续..." _
                ;;
            0|7) # Keep the former return key compatible.
                return 0
                ;;
            *)
                echo "❌ 无效选项。"
                sleep 1
                ;;
        esac
    done
}

cron_main() {
    local id="${1:-}"
    [ -n "$id" ] || die "cron 模式缺少设备 ID。"

    ensure_runner_installed

    if ! process_device_check "$id" 0; then
        log "❌ 设备 $id 自动检查失败。"
        return 1
    fi
}

case "${1:-menu}" in
    menu)
        remote_menu
        ;;
    cron)
        shift
        cron_main "${1:-}"
        ;;
    status)
        view_status
        ;;
    check)
        shift
        [ -n "${1:-}" ] || die "check 模式缺少设备 ID。"
        process_device_check "$1" 0
        ;;
    *)
        echo "用法：$0 [menu|cron <device-id>|status|check <device-id>]"
        exit 1
        ;;
esac
