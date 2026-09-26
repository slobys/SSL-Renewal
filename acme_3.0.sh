#!/bin/bash
set -e
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ACME_BIN="/root/.acme.sh/acme.sh"
DYNAMIC_DIR="/root/.ssl-renewal"
DYNAMIC_RUNNER="$DYNAMIC_DIR/dynamic_ip_cert.sh"
REMOTE_DIR="/root/.ssl-renewal/remote"
REMOTE_RUNNER="$REMOTE_DIR/remote_ip_ssl.sh"

CERT_KIND=""
IDENTIFIER=""
EMAIL=""
CA_SERVER=""
CHALLENGE_MODE="standalone"
VALIDATION_PORT="80"
FIREWALL_OPTION="3"
IP_VERSION=""
IP_CANONICAL=""
WEBROOT_PATH=""
RELOAD_CMD=""
KEY_PATH=""
CERT_PATH=""

die() {
    echo "❌ $*"
    exit 1
}

require_root() {
    if [ "${EUID}" -ne 0 ]; then
        die "请使用 root 用户运行本脚本。"
    fi
}

validate_email() {
    [[ "$1" =~ ^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$ ]]
}

validate_public_ip() {
    local result
    if ! result="$(python3 - "$1" <<'PY'
import ipaddress
import sys

try:
    ip = ipaddress.ip_address(sys.argv[1])
except ValueError:
    sys.exit(1)

print(f"{ip.version}|{ip.compressed}|{1 if ip.is_global else 0}")
PY
)"; then
        return 1
    fi

    local is_global
    IFS='|' read -r IP_VERSION IP_CANONICAL is_global <<< "$result"
    if [ "$is_global" != "1" ]; then
        return 2
    fi
    return 0
}

detect_os() {
    if [ ! -f /etc/os-release ]; then
        die "无法识别操作系统，请手动安装依赖。"
    fi

    # shellcheck disable=SC1091
    . /etc/os-release
    OS="${ID:-unknown}"
}

install_dependencies() {
    echo "📦 正在检查并安装依赖..."

    case "$OS" in
        ubuntu|debian)
            apt-get update -y
            DEBIAN_FRONTEND=noninteractive apt-get install -y \
                curl socat git cron python3 iproute2 ca-certificates openssl openssh-client
            systemctl enable --now cron >/dev/null 2>&1 || service cron start >/dev/null 2>&1 || true
            ;;
        centos|rhel|rocky|almalinux|fedora)
            local pm="yum"
            command -v dnf >/dev/null 2>&1 && pm="dnf"
            "$pm" install -y curl socat git cronie python3 iproute ca-certificates openssl openssh-clients
            systemctl enable --now crond >/dev/null 2>&1 || service crond start >/dev/null 2>&1 || true
            ;;
        *)
            die "暂不支持的操作系统：$OS"
            ;;
    esac
}

select_firewall_action() {
    echo
    echo "验证需要公网可访问 TCP ${VALIDATION_PORT} 端口。"
    echo "请选择防火墙处理方式："
    echo "1）关闭系统防火墙"
    echo "2）自动放行 TCP ${VALIDATION_PORT}"
    echo "3）不修改防火墙（已自行放行/使用云安全组/路由器端口映射）"
    read -r -p "输入选项（1-3）： " FIREWALL_OPTION

    case "$FIREWALL_OPTION" in
        1|2|3) ;;
        *) die "无效的防火墙选项。" ;;
    esac
}

configure_firewall() {
    case "$FIREWALL_OPTION" in
        1)
            if command -v ufw >/dev/null 2>&1; then
                ufw disable || true
            elif systemctl list-unit-files 2>/dev/null | grep -q '^firewalld'; then
                systemctl stop firewalld || true
                systemctl disable firewalld || true
            else
                echo "⚠️ 未检测到 UFW/firewalld，跳过关闭防火墙。"
            fi
            ;;
        2)
            if command -v ufw >/dev/null 2>&1; then
                ufw allow "${VALIDATION_PORT}/tcp" || true
            elif command -v firewall-cmd >/dev/null 2>&1; then
                firewall-cmd --permanent --add-port="${VALIDATION_PORT}/tcp" || true
                firewall-cmd --reload || true
            else
                echo "⚠️ 未检测到 UFW/firewalld，请手动放行 TCP ${VALIDATION_PORT}。"
            fi
            ;;
        3)
            echo "ℹ️ 未修改系统防火墙。"
            ;;
    esac

    echo "ℹ️ 云服务器还需检查安全组；家庭公网 IP 还需确认路由器/NAT 已转发 TCP ${VALIDATION_PORT}。"
}

select_ip_challenge() {
    local dynamic_mode="${1:-0}"

    echo
    echo "请选择 IP 地址验证方式："
    echo "1）HTTP-01 standalone（使用 TCP 80，端口必须空闲）"
    echo "2）HTTP-01 webroot（使用 TCP 80，适合已运行 Nginx/Apache）"
    echo "3）TLS-ALPN-01（使用 TCP 443，端口必须空闲）"
    if [ "$dynamic_mode" = "1" ]; then
        echo "提示：动态 IP 长期自动重签时，如果 80 已被 Web 服务占用，推荐选择 2。"
    fi
    read -r -p "输入选项（1-3）： " CHALLENGE_OPTION

    case "$CHALLENGE_OPTION" in
        1)
            CHALLENGE_MODE="standalone"
            VALIDATION_PORT="80"
            WEBROOT_PATH=""
            ;;
        2)
            CHALLENGE_MODE="webroot"
            VALIDATION_PORT="80"
            read -r -p "请输入 Web 根目录（例如 /var/www/html）： " WEBROOT_PATH
            [ -n "$WEBROOT_PATH" ] || die "Web 根目录不能为空。"
            ;;
        3)
            CHALLENGE_MODE="alpn"
            VALIDATION_PORT="443"
            WEBROOT_PATH=""
            ;;
        *)
            die "无效的验证方式。"
            ;;
    esac
}

check_challenge_port() {
    if [ "$CHALLENGE_MODE" = "webroot" ]; then
        return 0
    fi

    if command -v ss >/dev/null 2>&1; then
        if ss -ltnH 2>/dev/null | awk '{print $4}' | grep -Eq ":${VALIDATION_PORT}$"; then
            echo "❌ TCP ${VALIDATION_PORT} 已被其他程序占用，当前验证方式无法启动。"
            ss -ltnp 2>/dev/null | grep -E ":${VALIDATION_PORT}[[:space:]]" || true
            if [ "$VALIDATION_PORT" = "80" ]; then
                echo "可以重新运行并选择 HTTP-01 webroot，避免停止现有 Web 服务。"
            fi
            exit 1
        fi
    fi
}

ensure_webroot() {
    if [ "$CHALLENGE_MODE" != "webroot" ]; then
        return 0
    fi

    mkdir -p "$WEBROOT_PATH"
    [ -d "$WEBROOT_PATH" ] || die "无法创建 Web 根目录：$WEBROOT_PATH"
    [ -w "$WEBROOT_PATH" ] || die "Web 根目录不可写：$WEBROOT_PATH"
}

ensure_acme() {
    if [ ! -x "$ACME_BIN" ]; then
        echo "📥 未检测到 acme.sh，正在安装..."
        curl -fsSL https://get.acme.sh | sh -s email="$EMAIL"
    fi

    echo "⬆️ 正在升级 acme.sh，以确保支持 IP 证书和 ACME Profile..."
    "$ACME_BIN" --upgrade

    "$ACME_BIN" --install-cronjob >/dev/null 2>&1 || true

    echo "✅ 当前 acme.sh 版本："
    "$ACME_BIN" --version || true
}

register_account() {
    echo "👤 正在注册/检查 ACME 账户..."
    "$ACME_BIN" --register-account -m "$EMAIL" --server "$CA_SERVER"
}

cleanup_failed_order() {
    rm -f "$KEY_PATH" "$CERT_PATH"
    "$ACME_BIN" --remove -d "$IDENTIFIER" >/dev/null 2>&1 || true
}

issue_static_certificate() {
    local issue_args
    issue_args=(--issue -d "$IDENTIFIER" --server "$CA_SERVER")

    if [ "$CERT_KIND" = "ip" ]; then
        issue_args+=(--cert-profile shortlived --days 3)

        case "$CHALLENGE_MODE" in
            standalone)
                issue_args+=(--standalone)
                ;;
            webroot)
                issue_args+=(-w "$WEBROOT_PATH")
                ;;
            alpn)
                issue_args+=(--alpn)
                ;;
        esac

        if [ "$CHALLENGE_MODE" != "webroot" ]; then
            if [ "$IP_VERSION" = "4" ]; then
                issue_args+=(--listen-v4)
            else
                issue_args+=(--listen-v6)
            fi
        fi
    else
        issue_args+=(--standalone)
    fi

    echo
    echo "🚀 开始申请证书..."
    if ! "$ACME_BIN" "${issue_args[@]}"; then
        echo "❌ 证书申请失败，正在清理本次残留。"
        cleanup_failed_order
        exit 1
    fi

    echo "📂 正在安装证书到固定路径..."
    "$ACME_BIN" --install-cert -d "$IDENTIFIER" \
        --key-file "$KEY_PATH" \
        --fullchain-file "$CERT_PATH"
}

show_certificate_info() {
    echo
    echo "============== 申请完成 =============="
    echo "✅ SSL 证书申请成功！"
    echo "📄 证书路径: $CERT_PATH"
    echo "🔐 私钥路径: $KEY_PATH"

    if [ "$CERT_KIND" = "ip" ]; then
        echo "🌐 IP 地址: $IDENTIFIER"
        echo "🏷️ 证书配置: Let's Encrypt shortlived"
        echo "⏳ 有效期: 160 小时（约 6 天 16 小时）"
        echo "🔄 常规续期: acme.sh 自动续期，--days 3"
    else
        echo "🌐 域名: $IDENTIFIER"
        echo "🏷️ CA: $CA_SERVER"
        echo "🔄 续期策略: acme.sh 内置 cron"
    fi

    if crontab -l 2>/dev/null | grep -q 'acme.sh.*--cron'; then
        echo "✅ acme.sh 自动续期任务: 已启用"
    else
        echo "⚠️ 未检测到 acme.sh cron，请执行：$ACME_BIN --install-cronjob"
    fi

    if command -v openssl >/dev/null 2>&1 && [ -s "$CERT_PATH" ]; then
        echo
        echo "---------- 证书信息 ----------"
        openssl x509 -in "$CERT_PATH" -noout -issuer -dates -ext subjectAltName 2>/dev/null || true
    fi
    echo "======================================"
}

install_dynamic_runner() {
    mkdir -p "$DYNAMIC_DIR"
    chmod 700 "$DYNAMIC_DIR"

    if [ -f "$SCRIPT_DIR/dynamic_ip_cert.sh" ]; then
        install -m 700 "$SCRIPT_DIR/dynamic_ip_cert.sh" "$DYNAMIC_RUNNER"
    else
        echo "📥 正在下载动态 IP 检测脚本..."
        curl -fsSL \
            https://raw.githubusercontent.com/slobys/SSL-Renewal/main/dynamic_ip_cert.sh \
            -o "$DYNAMIC_RUNNER"
        chmod 700 "$DYNAMIC_RUNNER"
    fi
}

write_config_var() {
    local name="$1"
    local value="$2"
    printf '%s=%q\n' "$name" "$value"
}

write_dynamic_config() {
    local family="$1"
    local config_file="$DYNAMIC_DIR/dynamic-ip-v${family}.conf"
    local state_file="$DYNAMIC_DIR/dynamic-ip-v${family}.state"
    local cert_path="/root/dynamic-ip-v${family}.crt"
    local key_path="/root/dynamic-ip-v${family}.key"

    {
        write_config_var "ACME_BIN" "$ACME_BIN"
        write_config_var "IP_VERSION" "$family"
        write_config_var "EMAIL" "$EMAIL"
        write_config_var "CHALLENGE_MODE" "$CHALLENGE_MODE"
        write_config_var "WEBROOT_PATH" "$WEBROOT_PATH"
        write_config_var "RELOAD_CMD" "$RELOAD_CMD"
        write_config_var "CERT_PATH" "$cert_path"
        write_config_var "KEY_PATH" "$key_path"
        write_config_var "STATE_FILE" "$state_file"
    } > "$config_file"

    chmod 600 "$config_file"

    DYNAMIC_CONFIG_FILE="$config_file"
    DYNAMIC_STATE_FILE="$state_file"
    CERT_PATH="$cert_path"
    KEY_PATH="$key_path"
}

install_dynamic_cron() {
    local config_file="$1"
    local family="$2"
    local log_file="$DYNAMIC_DIR/dynamic-ip-v${family}.log"
    local cron_line="*/5 * * * * $DYNAMIC_RUNNER $config_file >> $log_file 2>&1"

    (
        crontab -l 2>/dev/null | grep -Fv "$DYNAMIC_RUNNER $config_file" || true
        echo "$cron_line"
    ) | crontab -

    echo "✅ 动态公网 IPv${family} 检测任务已安装：每 5 分钟检查一次。"
    echo "📝 日志路径: $log_file"
}

setup_dynamic_ip_certificate() {
    CERT_KIND="dynamic_ip"
    CA_SERVER="letsencrypt"

    echo
    echo "请选择要自动跟踪的公网 IP 类型："
    echo "1）IPv4"
    echo "2）IPv6"
    read -r -p "输入选项（1-2）： " FAMILY_OPTION
    case "$FAMILY_OPTION" in
        1) IP_VERSION="4" ;;
        2) IP_VERSION="6" ;;
        *) die "无效的 IP 类型。" ;;
    esac

    read -r -p "请输入电子邮件地址: " EMAIL
    validate_email "$EMAIL" || die "电子邮件地址格式不正确。"

    select_ip_challenge 1

    echo
    echo "证书每次签发/续期后，可以自动重载你的 Web 服务。"
    echo "例如：systemctl reload nginx"
    read -r -p "请输入重载命令（可直接回车留空）： " RELOAD_CMD

    select_firewall_action
    detect_os
    install_dependencies
    ensure_webroot
    check_challenge_port
    configure_firewall
    ensure_acme
    register_account
    install_dynamic_runner
    write_dynamic_config "$IP_VERSION"

    echo
    echo "🔎 正在执行第一次公网 IP 检测和证书签发..."
    if ! "$DYNAMIC_RUNNER" "$DYNAMIC_CONFIG_FILE"; then
        echo "❌ 动态 IP SSL 首次签发失败，未安装定时检测任务。"
        exit 1
    fi

    install_dynamic_cron "$DYNAMIC_CONFIG_FILE" "$IP_VERSION"

    IDENTIFIER="$(tr -d '\r\n[:space:]' < "$DYNAMIC_STATE_FILE")"
    echo
    echo "============== 动态 IP SSL 已启用 =============="
    echo "🌐 当前公网 IPv${IP_VERSION}: $IDENTIFIER"
    echo "📄 稳定证书路径: $CERT_PATH"
    echo "🔐 稳定私钥路径: $KEY_PATH"
    echo "🔄 IP 变化检测: 每 5 分钟"
    echo "♻️ IP 未变化时: 不重复申请证书"
    echo "🆕 IP 变化时: 自动为新 IP 重新签发并覆盖稳定证书路径"
    if [ -n "$RELOAD_CMD" ]; then
        echo "⚙️ 更新证书后执行: $RELOAD_CMD"
    fi
    echo "================================================="
}

show_dynamic_status_family() {
    local family="$1"
    local config_file="$DYNAMIC_DIR/dynamic-ip-v${family}.conf"

    if [ ! -f "$config_file" ]; then
        echo "IPv${family}: 未配置"
        return 0
    fi

    (
        # shellcheck disable=SC1090
        . "$config_file"
        local managed_ip="未知"
        if [ -f "$STATE_FILE" ]; then
            managed_ip="$(tr -d '\r\n[:space:]' < "$STATE_FILE")"
        fi

        echo "IPv${family}: 已配置"
        echo "  当前管理 IP: $managed_ip"
        echo "  验证方式: $CHALLENGE_MODE"
        echo "  证书路径: $CERT_PATH"
        echo "  私钥路径: $KEY_PATH"

        if crontab -l 2>/dev/null | grep -Fq "$DYNAMIC_RUNNER $config_file"; then
            echo "  自动检测: 已启用（每 5 分钟）"
        else
            echo "  自动检测: 未启用"
        fi

        if [ -s "$CERT_PATH" ] && command -v openssl >/dev/null 2>&1; then
            local expiry
            expiry="$(openssl x509 -in "$CERT_PATH" -noout -enddate 2>/dev/null | cut -d= -f2- || true)"
            [ -n "$expiry" ] && echo "  证书到期: $expiry"
        fi
    )
}

force_dynamic_check() {
    local family="$1"
    local config_file="$DYNAMIC_DIR/dynamic-ip-v${family}.conf"

    [ -f "$config_file" ] || die "尚未配置动态公网 IPv${family} SSL。"
    [ -x "$DYNAMIC_RUNNER" ] || die "动态 IP 检测脚本不存在：$DYNAMIC_RUNNER"

    "$DYNAMIC_RUNNER" "$config_file"
}

remove_dynamic_monitor() {
    local family="$1"
    local config_file="$DYNAMIC_DIR/dynamic-ip-v${family}.conf"
    local state_file="$DYNAMIC_DIR/dynamic-ip-v${family}.state"
    local log_file="$DYNAMIC_DIR/dynamic-ip-v${family}.log"

    if [ ! -f "$config_file" ]; then
        echo "ℹ️ IPv${family} 动态 SSL 未配置。"
        return 0
    fi

    (
        crontab -l 2>/dev/null | grep -Fv "$DYNAMIC_RUNNER $config_file" || true
    ) | crontab -

    rm -f "$config_file" "$state_file" "$log_file"
    echo "✅ 已删除 IPv${family} 动态 IP 自动检测配置。"
    echo "ℹ️ 已签发的 /root/dynamic-ip-v${family}.crt 和 .key 保留，不会删除。"

    if [ ! -f "$DYNAMIC_DIR/dynamic-ip-v4.conf" ] && [ ! -f "$DYNAMIC_DIR/dynamic-ip-v6.conf" ]; then
        rm -f "$DYNAMIC_RUNNER"
    fi
}

manage_dynamic_ip() {
    while true; do
        clear 2>/dev/null || true
        echo "============== 动态 IP SSL 管理 =============="
        echo "1）查看状态"
        echo "2）立即检查/更新 IPv4"
        echo "3）立即检查/更新 IPv6"
        echo "4）删除 IPv4 自动检测"
        echo "5）删除 IPv6 自动检测"
        echo "6）返回主菜单"
        echo "=============================================="
        read -r -p "请输入选项（1-6）： " DYNAMIC_OPTION

        case "$DYNAMIC_OPTION" in
            1)
                echo
                show_dynamic_status_family 4
                echo
                show_dynamic_status_family 6
                echo
                read -r -p "按回车继续..." _
                ;;
            2)
                force_dynamic_check 4
                read -r -p "按回车继续..." _
                ;;
            3)
                force_dynamic_check 6
                read -r -p "按回车继续..." _
                ;;
            4)
                remove_dynamic_monitor 4
                read -r -p "按回车继续..." _
                ;;
            5)
                remove_dynamic_monitor 6
                read -r -p "按回车继续..." _
                ;;
            6)
                return 0
                ;;
            *)
                echo "❌ 无效选项。"
                sleep 1
                ;;
        esac
    done
}

manage_remote_ip_ssl() {
    detect_os
    install_dependencies

    mkdir -p "$REMOTE_DIR"
    chmod 700 "$REMOTE_DIR"

    if [ -f "$SCRIPT_DIR/remote_ip_ssl.sh" ]; then
        install -m 700 "$SCRIPT_DIR/remote_ip_ssl.sh" "$REMOTE_RUNNER"
    else
        echo "📥 正在下载远程 IP SSL 管理脚本..."
        curl -fsSL \
            https://raw.githubusercontent.com/slobys/SSL-Renewal/main/remote_ip_ssl.sh \
            -o "$REMOTE_RUNNER"
        chmod 700 "$REMOTE_RUNNER"
    fi

    "$REMOTE_RUNNER" menu
}

require_root

while true; do
    clear 2>/dev/null || true
    echo "============== SSL证书管理菜单 =============="
    echo "1）申请域名 SSL 证书"
    echo "2）申请固定公网 IP SSL 证书"
    echo "3）动态公网 IP SSL（本机IP变化自动重签）"
    echo "4）本机动态 IP SSL 管理"
    echo "5）远程 IP SSL（OpenWrt/远程设备）"
    echo "6）重置环境（重新部署脚本）"
    echo "7）退出"
    echo "============================================"
    read -r -p "请输入选项（1-7）： " MAIN_OPTION

    case "$MAIN_OPTION" in
        1)
            CERT_KIND="domain"
            break
            ;;
        2)
            CERT_KIND="ip"
            break
            ;;
        3)
            setup_dynamic_ip_certificate
            exit 0
            ;;
        4)
            manage_dynamic_ip
            ;;
        5)
            manage_remote_ip_ssl
            ;;
        6)
            echo "⚠️ 正在重置脚本部署环境..."
            rm -rf /tmp/acme
            echo "📦 正在重新执行 acme.sh ..."
            sleep 1
            bash <(curl -fsSL https://raw.githubusercontent.com/slobys/SSL-Renewal/main/acme.sh)
            exit 0
            ;;
        7)
            echo "👋 已退出。"
            exit 0
            ;;
        *)
            echo "❌ 无效选项，请重新输入。"
            sleep 1
            ;;
    esac

    if [ "$CERT_KIND" = "domain" ] || [ "$CERT_KIND" = "ip" ]; then
        break
    fi
done

if [ "$CERT_KIND" = "domain" ]; then
    read -r -p "请输入域名: " IDENTIFIER
    [ -n "$IDENTIFIER" ] || die "域名不能为空。"
    [[ "$IDENTIFIER" != *[[:space:]]* ]] || die "域名中不能包含空格。"

    read -r -p "请输入电子邮件地址: " EMAIL
    validate_email "$EMAIL" || die "电子邮件地址格式不正确。"

    echo
    echo "请选择证书颁发机构（CA）："
    echo "1）Let's Encrypt"
    echo "2）Buypass"
    echo "3）ZeroSSL"
    read -r -p "输入选项（1-3）： " CA_OPTION
    case "$CA_OPTION" in
        1) CA_SERVER="letsencrypt" ;;
        2) CA_SERVER="buypass" ;;
        3) CA_SERVER="zerossl" ;;
        *) die "无效的 CA 选项。" ;;
    esac

    CHALLENGE_MODE="standalone"
    VALIDATION_PORT="80"
else
    read -r -p "请输入固定公网 IP 地址（IPv4 或 IPv6）: " IDENTIFIER
    [ -n "$IDENTIFIER" ] || die "IP 地址不能为空。"

    read -r -p "请输入电子邮件地址: " EMAIL
    validate_email "$EMAIL" || die "电子邮件地址格式不正确。"

    CA_SERVER="letsencrypt"
    select_ip_challenge 0

    echo
    echo "ℹ️ IP 证书固定使用 Let's Encrypt shortlived 配置。"
    echo "ℹ️ 证书有效期为 160 小时，因此必须依赖自动续期。"
fi

select_firewall_action
detect_os
install_dependencies
ensure_webroot

if [ "$CERT_KIND" = "ip" ]; then
    set +e
    validate_public_ip "$IDENTIFIER"
    IP_CHECK_STATUS=$?
    set -e

    case "$IP_CHECK_STATUS" in
        0)
            IDENTIFIER="$IP_CANONICAL"
            echo "✅ 已确认是公网 IPv${IP_VERSION} 地址：$IDENTIFIER"
            ;;
        1)
            die "IP 地址格式无效：$IDENTIFIER"
            ;;
        2)
            die "该地址不是可公开路由的公网 IP，Let's Encrypt 不会为私网/保留地址签发公开证书。"
            ;;
        *)
            die "IP 地址检查失败。"
            ;;
    esac
fi

SAFE_NAME="${IDENTIFIER//:/_}"
SAFE_NAME="${SAFE_NAME//\//_}"
KEY_PATH="/root/${SAFE_NAME}.key"
CERT_PATH="/root/${SAFE_NAME}.crt"

check_challenge_port
configure_firewall
ensure_acme
register_account
issue_static_certificate
show_certificate_info
