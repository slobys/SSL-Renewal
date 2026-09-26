#!/bin/sh
# Portable entry point: OpenWrt must be detected BEFORE requiring Bash or Git.
set -eu
[ "$(id -u)" = 0 ] || { echo '请使用 root 运行。'; exit 1; }
DOWNLOAD_DIR=$(mktemp -d /tmp/ssl-renewal.XXXXXX)
trap 'rm -rf "$DOWNLOAD_DIR"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

fetch_script() {
    if command -v curl >/dev/null 2>&1; then
        curl -q -fsS --proto '=https' --connect-timeout 10 --max-time 120 "$1" -o "$2"
    elif command -v uclient-fetch >/dev/null 2>&1; then
        uclient-fetch -O "$2" "$1"
    elif command -v wget >/dev/null 2>&1; then
        wget -T 30 -O "$2" "$1"
    else
        echo '请先安装 curl 或支持 HTTPS 的 wget/uclient-fetch。' >&2
        return 1
    fi
}

if [ -f /etc/openwrt_release ]; then
    echo '检测到 OpenWrt / iStoreOS：进入软路由本机模式，无需 Python、Git 或云服务器。'
    fetch_script https://raw.githubusercontent.com/slobys/SSL-Renewal/main/openwrt_ip_ssl.sh "$DOWNLOAD_DIR/openwrt_ip_ssl.sh"
    sh -n "$DOWNLOAD_DIR/openwrt_ip_ssl.sh"
    TARGET_DIR=/root/.ssl-renewal/openwrt
    mkdir -p "$TARGET_DIR"
    chmod 700 "$TARGET_DIR"
    cp "$DOWNLOAD_DIR/openwrt_ip_ssl.sh" "$TARGET_DIR/openwrt_ip_ssl.sh.new"
    chmod 700 "$TARGET_DIR/openwrt_ip_ssl.sh.new"
    mv -f "$TARGET_DIR/openwrt_ip_ssl.sh.new" "$TARGET_DIR/openwrt_ip_ssl.sh"
    sh "$TARGET_DIR/openwrt_ip_ssl.sh" menu
    exit 0
fi

# Existing Linux server modes remain Bash-based. Never run these package commands
# on OpenWrt. Do not perform an unrelated system/package upgrade.
command -v bash >/dev/null 2>&1 || { echo 'Linux 服务器模式需要 Bash，请先安装。'; exit 1; }
if ! command -v git >/dev/null 2>&1; then
    if [ -f /etc/os-release ]; then . /etc/os-release; OS_ID=${ID:-unknown}; else OS_ID=unknown; fi
    case "$OS_ID" in
        ubuntu|debian) apt-get update -y; apt-get install git -y;;
        centos|rhel|rocky|almalinux|fedora)
            PM=yum
            if command -v dnf >/dev/null 2>&1; then PM=dnf; fi
            "$PM" install git -y
            ;;
        *) echo '此系统请先手动安装 Git。'; exit 1;;
    esac
fi

[ ! -e /root/.ssl-renewal/server.uninstalling ] || { echo '卸载操作尚未结束，暂不重装。'; exit 1; }
git clone --depth 1 --branch main https://github.com/slobys/SSL-Renewal.git "$DOWNLOAD_DIR/repo"
for file in acme.sh acme_3.0.sh dynamic_ip_cert.sh remote_ip_ssl.sh openwrt_ip_ssl.sh; do
    bash -n "$DOWNLOAD_DIR/repo/$file"
done
for file in acme.sh acme_3.0.sh dynamic_ip_cert.sh remote_ip_ssl.sh openwrt_ip_ssl.sh; do
    install -m 700 "$DOWNLOAD_DIR/repo/$file" "/root/$file"
done
install -m 700 "$DOWNLOAD_DIR/repo/uninstall_server.py" /root/uninstall_server.py
# Reinstallation only clears our stop marker; it does not silently recreate cron jobs.
rm -f /root/.ssl-renewal/server.uninstalled
# Retain the legacy remote runner for existing installations; do not migrate,
# disable or delete anyone's old scheduled remote jobs merely by updating scripts.
bash /root/acme_3.0.sh
