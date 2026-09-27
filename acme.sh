#!/bin/sh
# Portable entry point: OpenWrt must be detected BEFORE requiring Bash or Git.
set -eu
[ "$(id -u)" = 0 ] || { echo '请使用 root 运行。'; exit 1; }
DOWNLOAD_DIR=$(mktemp -d /tmp/ssl-renewal.XXXXXX)
INSTALL_BACKUP=''; INSTALL_CHANGED=''; INSTALL_COMPLETE=0; INSTALL_LOCK=''; INSTALL_STAGE=''
cleanup_install() {
    if [ "$INSTALL_COMPLETE" != 1 ] && [ -n "$INSTALL_BACKUP" ]; then
        for target in $INSTALL_CHANGED; do
            name=${target##*/}
            if [ -f "$INSTALL_BACKUP/$name" ]; then
                cp -p "$INSTALL_BACKUP/$name" "$target.rollback" && mv -f "$target.rollback" "$target" || echo "回滚失败，请从 $INSTALL_BACKUP 恢复 $name。" >&2
            else rm -f "$target"; fi
        done
    fi
    [ -z "$INSTALL_STAGE" ] || rm -f "$INSTALL_STAGE"
    [ -z "$INSTALL_LOCK" ] || rmdir "$INSTALL_LOCK" 2>/dev/null || true
    rm -rf "$DOWNLOAD_DIR"
}
trap cleanup_install EXIT
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

# SHA256SUMS is an HTTPS-delivered consistency manifest, not a signature or a
# substitute for trusting the repository. A moving-main mismatch fails closed.
check_download() {
    name=$1; checked_file=$2; manifest=$3
    [ -s "$checked_file" ] && [ -s "$manifest" ] || { echo "下载内容为空：$name；旧程序保留。" >&2; return 1; }
    command -v sha256sum >/dev/null 2>&1 || { echo '缺少 sha256sum，未覆盖旧程序。' >&2; return 1; }
    expected=$(awk -v name="$name" '$2==name {hash=$1; n++} END {if(n==1 && length(hash)==64 && hash !~ /[^0-9a-f]/) print hash; else exit 1}' "$manifest") || return 1
    actual=$(sha256sum "$checked_file") || return 1
    [ "${actual%% *}" = "$expected" ] || { echo "文件校验不符：$name（可能更新期间版本变化）；旧程序保留，请重新运行。" >&2; return 1; }
    case "$name" in
        openwrt_ip_ssl.sh)
            sh -n "$checked_file" && grep -q '^ow_main() {' "$checked_file" || return 1
            [ "$(sh "$checked_file" self-test)" = SSL-RENEWAL-OPENWRT-READY-v1 ] || return 1;;
        *.sh) bash -n "$checked_file";;
        uninstall_server.py) grep -q 'SSL-Renewal server uninstaller' "$checked_file";;
        *) return 1;;
    esac
}
prepare_publish() {
    for dir in /root/.ssl-renewal /root/ssl-renewal-backups; do
        [ ! -L "$dir" ] || { echo "拒绝符号链接目录：$dir" >&2; return 1; }
        mkdir -p "$dir" && chmod 700 "$dir" || return 1
    done
    mkdir /root/.ssl-renewal/install.lock 2>/dev/null || { echo '安装锁已存在，请确认其他安装已结束；未覆盖旧程序。' >&2; return 1; }
    INSTALL_LOCK=/root/.ssl-renewal/install.lock
    INSTALL_BACKUP=$(mktemp -d /root/ssl-renewal-backups/update-XXXXXX)
    chmod 700 "$INSTALL_BACKUP"
}
publish_file() {
    source=$1; target=$2; name=${target##*/}
    [ ! -L "$target" ] && { [ ! -e "$target" ] || [ -f "$target" ]; } || return 1
    [ ! -e "$target" ] || cp -p "$target" "$INSTALL_BACKUP/$name" || return 1
    INSTALL_STAGE="$target.sslrenewal-new.$$"
    cp "$source" "$INSTALL_STAGE" && chmod 700 "$INSTALL_STAGE" || return 1
    INSTALL_CHANGED="$target $INSTALL_CHANGED"
    mv -f "$INSTALL_STAGE" "$target" || return 1
    INSTALL_STAGE=''
}
finish_publish() {
    INSTALL_COMPLETE=1
    rmdir "$INSTALL_LOCK"
    INSTALL_LOCK=''
    echo "脚本已校验并更新；旧程序备份：$INSTALL_BACKUP"
}

if [ -f /etc/openwrt_release ]; then
    echo '检测到 OpenWrt / iStoreOS：进入软路由本机模式，无需 Python、Git 或云服务器。'
    fetch_script https://raw.githubusercontent.com/slobys/SSL-Renewal/main/SHA256SUMS "$DOWNLOAD_DIR/SHA256SUMS"
    fetch_script https://raw.githubusercontent.com/slobys/SSL-Renewal/main/openwrt_ip_ssl.sh "$DOWNLOAD_DIR/openwrt_ip_ssl.sh"
    check_download openwrt_ip_ssl.sh "$DOWNLOAD_DIR/openwrt_ip_ssl.sh" "$DOWNLOAD_DIR/SHA256SUMS"
    prepare_publish
    TARGET_DIR=/root/.ssl-renewal/openwrt
    [ ! -L "$TARGET_DIR" ] || { echo '管理目录不能是符号链接。'; exit 1; }
    mkdir -p "$TARGET_DIR"
    chmod 700 "$TARGET_DIR"
    publish_file "$DOWNLOAD_DIR/openwrt_ip_ssl.sh" "$TARGET_DIR/openwrt_ip_ssl.sh"
    finish_publish
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
for file in acme.sh acme_3.0.sh dynamic_ip_cert.sh remote_ip_ssl.sh openwrt_ip_ssl.sh uninstall_server.py; do
    check_download "$file" "$DOWNLOAD_DIR/repo/$file" "$DOWNLOAD_DIR/repo/SHA256SUMS"
done
prepare_publish
for file in acme.sh acme_3.0.sh dynamic_ip_cert.sh remote_ip_ssl.sh openwrt_ip_ssl.sh uninstall_server.py; do
    publish_file "$DOWNLOAD_DIR/repo/$file" "/root/$file"
done
finish_publish
# Reinstallation only clears our stop marker; it does not silently recreate cron jobs.
rm -f /root/.ssl-renewal/server.uninstalled
# Retain the legacy remote runner for existing installations; do not migrate,
# disable or delete anyone's old scheduled remote jobs merely by updating scripts.
bash /root/acme_3.0.sh
