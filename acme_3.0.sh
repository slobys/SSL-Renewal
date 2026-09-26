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
DEPENDENCIES_READY=0
DETECTED_IPV4=""
DETECTED_IPV6=""
IP_SELECTION_MODE=""
PORT80_STATE="unknown"
PORT443_STATE="unknown"
PORT80_LISTENERS=""
PORT443_LISTENERS=""
RECOMMENDED_CHALLENGE=""

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

# One validator is shared by manual input and discovery responses.
ip_tool() {
    python3 - "$@" <<'PY'
import concurrent.futures
import ipaddress
import subprocess
import sys


def address(raw):
    raw = raw.strip()
    if raw.startswith('[') and raw.endswith(']') and ':' in raw:
        raw = raw[1:-1]
    if '%' in raw:
        raise ValueError('IPv6 scope identifiers are not supported')
    ip = ipaddress.ip_address(raw)
    if (not ip.is_global or ip.is_multicast or ip.is_reserved
            or ip.is_loopback or ip.is_link_local or ip.is_unspecified
            or getattr(ip, 'ipv4_mapped', None) is not None):
        raise PermissionError('Not a public unicast address')
    return ip


def discover(family):
    hosts = ('4.ipw.cn', 'api4.ipify.org', 'ipv4.icanhazip.com') if family == 4 else (
        '6.ipw.cn', 'api6.ipify.org', 'ipv6.icanhazip.com')
    for host in hosts:
        try:
            # -q must be first: do not let .curlrc or proxy variables change
            # the observed egress address. Router-level proxies may still apply.
            result = subprocess.run(
                ['curl', '-q', '--noproxy', '*', '--proxy', '',
                 '--proto', '=https', '-{}'.format(family), '-fsS',
                 '--connect-timeout', '3', '--max-time', '5',
                 '--max-filesize', '1024', 'https://' + host],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, timeout=6, check=False)
            if result.returncode != 0 or len(result.stdout) > 1024:
                continue
            ip = address(result.stdout.decode('ascii'))
            if ip.version == family:
                return '{}|{}|{}'.format(family, ip.compressed, host)
        except (OSError, ValueError, PermissionError, subprocess.TimeoutExpired):
            continue
    return '{}||'.format(family)


if sys.argv[1] == 'validate':
    try:
        ip = address(sys.argv[2])
    except PermissionError:
        sys.exit(2)
    except ValueError:
        sys.exit(1)
    print('{}|{}'.format(ip.version, ip.compressed))
elif sys.argv[1] == 'discover':
    # A missing IPv6 route does not hold up the IPv4 probe.
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        for line in pool.map(discover, (4, 6)):
            print(line)
else:
    sys.exit(1)
PY
}

validate_public_ip() {
    local result rc
    IP_VERSION=""
    IP_CANONICAL=""
    if result="$(ip_tool validate "$1")"; then
        IFS='|' read -r IP_VERSION IP_CANONICAL <<< "$result"
        return 0
    else
        rc=$?
        return "$rc"
    fi
}

ensure_ip_selection_tools() {
    if ! command -v python3 >/dev/null 2>&1 ||
       ! command -v curl >/dev/null 2>&1 ||
       ! command -v ss >/dev/null 2>&1; then
        detect_os
        install_dependencies
    fi
}

detect_public_ips() {
    local results family address source
    DETECTED_IPV4=""
    DETECTED_IPV6=""
    echo "🔍 正在并行检测公网 IPv4 / IPv6（检测失败时可手动输入）..."
    results="$(ip_tool discover)" || results=""
    while IFS='|' read -r family address source; do
        case "$family" in
            4) DETECTED_IPV4="$address" ;;
            6) DETECTED_IPV6="$address" ;;
        esac
        if [ -n "$address" ]; then
            printf '  IPv%s：%s（来源：%s）\n' "$family" "$address" "$source"
        fi
    done <<< "$results"
    [ -n "$DETECTED_IPV4" ] || echo "  IPv4：未检测到（不等于没有公网 IPv4）"
    [ -n "$DETECTED_IPV6" ] || echo "  IPv6：未检测到（可手动填写或重新检测）"
    echo "ℹ️ 检测结果是出口地址，不证明该 IP 属于本机或支持公网入站。"
    echo "ℹ️ CGNAT、透明代理、多出口网络可能影响结果，请核对云控制台/路由器 WAN 地址。"
}

select_public_ip() {
    ensure_ip_selection_tools
    detect_public_ips
    local choice default candidate rc
    while true; do
        default=3
        if [ -n "$DETECTED_IPV4" ]; then
            default=1
        elif [ -n "$DETECTED_IPV6" ]; then
            default=2
        fi
        echo
        echo "============== 公网 IP 选择 =============="
        echo "1）使用检测到的 IPv4：${DETECTED_IPV4:-不可选}"
        echo "2）使用检测到的 IPv6：${DETECTED_IPV6:-不可选}"
        echo "3）手动输入公网 IP"
        echo "4）重新检测"
        echo "0）取消本次申请"
        read -r -p "请选择 [默认 $default]： " choice || return 1
        choice="${choice:-$default}"
        IP_SELECTION_MODE="自动检测"
        case "$choice" in
            1) candidate="$DETECTED_IPV4" ;;
            2) candidate="$DETECTED_IPV6" ;;
            3)
                IP_SELECTION_MODE="手动输入"
                read -r -p "请输入公网 IPv4 / IPv6（仅地址，不带协议、端口或网段）： " candidate || return 1
                ;;
            4) detect_public_ips; continue ;;
            0) return 1 ;;
            *) echo "❌ 无效选项，请重新选择。"; continue ;;
        esac
        if [ -z "$candidate" ]; then
            echo "⚠️ 当前没有可用地址，请手动输入或重新检测。"
            continue
        fi
        if validate_public_ip "$candidate"; then
            IDENTIFIER="$IP_CANONICAL"
            echo "✅ 已选择 IPv${IP_VERSION}：$IDENTIFIER（$IP_SELECTION_MODE）"
            if [ "$IP_SELECTION_MODE" = "手动输入" ]; then
                echo "ℹ️ 手动填写不会转移验证地点；目标 IP 的验证请求必须能到达本机。"
                echo "   云服务器替家中软路由申请，请使用主菜单 5 的远程模式。"
            fi
            return 0
        else
            rc=$?
            if [ "$rc" -eq 2 ]; then
                echo "❌ 不能使用私网、CGNAT、回环、保留或组播地址，请重新输入。"
            else
                echo "❌ IP 格式无效，请只填写地址；IPv6 可以带一对方括号。"
            fi
        fi
    done
}

refresh_port_status() {
    local listeners
    PORT80_STATE="unknown"
    PORT443_STATE="unknown"
    PORT80_LISTENERS=""
    PORT443_LISTENERS=""
    if ! command -v ss >/dev/null 2>&1; then
        return 0
    fi
    if ! listeners="$(ss -ltnpH 2>/dev/null)"; then
        if ! listeners="$(ss -ltnH 2>/dev/null)"; then
            return 0
        fi
    fi
    # Match the LOCAL endpoint only; :8080 and peer endpoints are not :80.
    PORT80_LISTENERS="$(printf '%s\n' "$listeners" | awk '$4 ~ /:80$/ { print }')"
    PORT443_LISTENERS="$(printf '%s\n' "$listeners" | awk '$4 ~ /:443$/ { print }')"
    PORT80_STATE="free"
    PORT443_STATE="free"
    [ -z "$PORT80_LISTENERS" ] || PORT80_STATE="busy"
    [ -z "$PORT443_LISTENERS" ] || PORT443_STATE="busy"
}

show_port_status() {
    local port state lines
    for port in 80 443; do
        if [ "$port" = "80" ]; then
            state="$PORT80_STATE"; lines="$PORT80_LISTENERS"
        else
            state="$PORT443_STATE"; lines="$PORT443_LISTENERS"
        fi
        case "$state" in
            free) echo "  TCP $port：本机未发现监听（公网可达性尚未验证）" ;;
            busy)
                echo "  TCP $port：已被占用"
                printf '%s\n' "$lines" | tr -d '\000-\010\013-\037\177' | sed -n '1,4s/^/    /p'
                ;;
            *) echo "  TCP $port：无法确定（不会当作空闲）" ;;
        esac
    done
}

recommend_challenge() {
    RECOMMENDED_CHALLENGE=""
    if [ "$PORT80_STATE" = "free" ]; then
        RECOMMENDED_CHALLENGE=1
    elif [ "$PORT80_STATE" = "busy" ] &&
         printf '%s\n' "$PORT80_LISTENERS" | grep -Ei '(nginx|apache2|httpd|uhttpd)' >/dev/null; then
        RECOMMENDED_CHALLENGE=2
    elif [ "$PORT80_STATE" = "busy" ] && [ "$PORT443_STATE" = "free" ]; then
        RECOMMENDED_CHALLENGE=3
    fi
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
    [ "$DEPENDENCIES_READY" -eq 0 ] || return 0
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
    DEPENDENCIES_READY=1
}

select_firewall_action() {
    local confirm
    while true; do
        echo
        echo "验证需要公网可访问 TCP ${VALIDATION_PORT}，续期时也需要。"
        echo "1）关闭系统防火墙【不推荐，需再次确认】"
        echo "2）仅放行 TCP ${VALIDATION_PORT}（不自动开启防火墙）"
        echo "3）不修改防火墙【默认】（云安全组/NAT仍需自行检查）"
        read -r -p "请选择 [默认 3]： " FIREWALL_OPTION || die "输入已结束，未修改防火墙。"
        FIREWALL_OPTION="${FIREWALL_OPTION:-3}"
        case "$FIREWALL_OPTION" in
            1)
                read -r -p "关闭防火墙会扩大暴露面，输入 CLOSE 确认： " confirm || die "已取消。"
                [ "$confirm" = "CLOSE" ] && return 0
                echo "未确认，返回选择。"
                ;;
            2|3) return 0 ;;
            *) echo "❌ 无效选项，请重新选择。" ;;
        esac
    done
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
    local dynamic_mode="${1:-0}" selected_state
    ensure_ip_selection_tools
    while true; do
        refresh_port_status
        recommend_challenge
        echo
        echo "============== 验证环境 =============="
        show_port_status
        echo "1）HTTP-01 临时服务（80端口，需保持空闲）"
        echo "2）HTTP-01 网站目录（80端口，复用已有网站，不停止服务）"
        echo "3）TLS-ALPN-01 临时服务（443端口，80不可用时考虑）"
        echo "4）重新检测端口"
        echo "0）取消本次申请"
        case "$RECOMMENDED_CHALLENGE" in
            1) echo "⭐ 建议 1：本机 80 未发现监听；仍需确认公网入站。" ;;
            2) echo "⭐ 建议 2：80 有常见 Web 服务；需填写该 IP 实际使用的网站目录。" ;;
            3) echo "⭐ 建议 3：80 已占用、443 未发现监听；仍需确认公网入站。" ;;
            *) echo "⚠️ 无法可靠推荐，请检查现有服务或手动配置网站目录。" ;;
        esac
        echo "ℹ️ 80/443只是验证方式不同，最终证书不绑定验证端口。"
        if [ "$dynamic_mode" = "1" ]; then
            echo "ℹ️ 长期自动续期必须保留验证条件；443开始提供HTTPS后不能再被临时服务独占。"
        fi
        read -r -p "请选择${RECOMMENDED_CHALLENGE:+ [默认 $RECOMMENDED_CHALLENGE]}： " CHALLENGE_OPTION || return 1
        CHALLENGE_OPTION="${CHALLENGE_OPTION:-$RECOMMENDED_CHALLENGE}"
        case "$CHALLENGE_OPTION" in
            1|3)
                selected_state="$PORT80_STATE"
                [ "$CHALLENGE_OPTION" = "1" ] || selected_state="$PORT443_STATE"
                if [ "$selected_state" != "free" ]; then
                    echo "❌ 所选端口已占用或状态未知，不会停止现有服务，请换一种方式。"
                    continue
                fi
                WEBROOT_PATH=""
                if [ "$CHALLENGE_OPTION" = "1" ]; then
                    CHALLENGE_MODE="standalone"; VALIDATION_PORT=80
                else
                    CHALLENGE_MODE="alpn"; VALIDATION_PORT=443
                fi
                return 0
                ;;
            2)
                read -r -p "现有网站的绝对根目录（如 /var/www/html，留空返回）： " WEBROOT_PATH || return 1
                if [[ "$WEBROOT_PATH" != /* ]] || [ "$WEBROOT_PATH" = "/" ] ||
                   [ ! -d "$WEBROOT_PATH" ] || [ ! -w "$WEBROOT_PATH" ]; then
                    echo "❌ 请填写存在且可写的网站目录；不会自动猜目录或创建网站。"
                    continue
                fi
                CHALLENGE_MODE="webroot"; VALIDATION_PORT=80
                echo "ℹ️ 请确保 http://目标IP/.well-known/acme-challenge/ 映射到此目录。"
                echo "   仅有目录不够；Nginx/Apache路由、80入站、NAT仍需正确配置。"
                return 0
                ;;
            4) continue ;;
            0) return 1 ;;
            *) echo "❌ 无效选项，请重新选择。" ;;
        esac
    done
}

confirm_ip_request() {
    local answer
    echo
    echo "============== 申请信息确认 =============="
    echo "目标：$IDENTIFIER（IPv$IP_VERSION，$IP_SELECTION_MODE）"
    echo "验证：$CHALLENGE_MODE，公网 TCP $VALIDATION_PORT"
    [ "$CHALLENGE_MODE" != "webroot" ] || echo "网站目录：$WEBROOT_PATH"
    echo "固定 IP 模式不会自动追踪 IP 变化；需要追踪请选择主菜单 3。"
    read -r -p "继续申请？[Y/n]： " answer || return 1
    case "$answer" in
        ""|y|Y|yes|YES) return 0 ;;
        *) echo "已取消，未申请证书。"; return 1 ;;
    esac
}

check_challenge_port() {
    if [ "$CHALLENGE_MODE" = "webroot" ]; then
        return 0
    fi

    # Recheck immediately before issuance: a listener may have appeared since the menu.
    refresh_port_status
    local state="$PORT80_STATE"
    [ "$VALIDATION_PORT" = "80" ] || state="$PORT443_STATE"
    if [ "$state" != "free" ]; then
        show_port_status
        die "TCP ${VALIDATION_PORT} 已占用或无法检测；不停止现有服务，请重新选择验证方式。"
    fi
}

ensure_webroot() {
    if [ "$CHALLENGE_MODE" != "webroot" ]; then
        return 0
    fi

    [ -d "$WEBROOT_PATH" ] || die "Web 根目录不存在，请配置现有网站目录：$WEBROOT_PATH"
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
    local issue_rc=0
    "$ACME_BIN" "${issue_args[@]}" || issue_rc=$?
    case "$issue_rc" in
        0) ;;
        2) echo "ℹ️ acme.sh 跳过了重复签发，尝试安装已有证书；不强制重签。" ;;
        *) die "证书申请失败，已保留现有证书、私钥及续期记录，请检查验证日志。" ;;
    esac

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

    select_ip_challenge 1 || { echo "已取消。"; return 0; }

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

main() {
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
    select_public_ip || { echo "已取消。"; return 0; }

    read -r -p "请输入电子邮件地址: " EMAIL
    validate_email "$EMAIL" || die "电子邮件地址格式不正确。"

    CA_SERVER="letsencrypt"
    select_ip_challenge 0 || { echo "已取消。"; return 0; }
    confirm_ip_request || return 0

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
}

# Sourcing exposes functions for offline tests without opening menus or deploying.
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
