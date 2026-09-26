#!/bin/bash
set -e
set -o pipefail

if [ "${EUID}" -ne 0 ]; then
    echo "❌ 请使用 root 用户运行此安装入口。"
    exit 1
fi

# ========= 检查并安装 git =========
echo "🔍 正在检查 git 是否已安装..."
if ! command -v git >/dev/null 2>&1; then
    echo "⚠️ 未检测到 git，正在尝试安装..."

    # 判断系统类型
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_ID=$ID
    else
        OS_ID=$(uname -s)
    fi

    if [[ "$OS_ID" == "debian" || "$OS_ID" == "ubuntu" ]]; then
        apt-get update -y
        apt-get install git -y || {
            echo "❌ git 安装失败，请先手动运行以下命令："
            echo "sudo apt update -y && sudo apt install git -y"
            exit 1
        }
    elif [[ "$OS_ID" =~ ^(centos|rhel|rocky|almalinux|fedora)$ ]]; then
        PM=yum
        command -v dnf >/dev/null 2>&1 && PM=dnf
        "$PM" install git -y || {
            echo "❌ git 安装失败，请先手动运行以下命令："
            echo "sudo yum update -y && sudo yum install git -y"
            exit 1
        }
    else
        echo "❌ 无法识别的系统类型，请手动安装 git。"
        exit 1
    fi
else
    echo "✅ git 已安装。"
fi

# ========= 只更新运行脚本，保留证书、配置和用户文件 =========
# Do not move every repository entry into /root: tests/docs directories can
# collide on a second invocation. Only install the four known runtime scripts.
DOWNLOAD_DIR="$(mktemp -d /tmp/ssl-renewal.XXXXXX)"
trap 'rm -rf -- "$DOWNLOAD_DIR"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
git clone --depth 1 --branch main https://github.com/slobys/SSL-Renewal.git "$DOWNLOAD_DIR/repo"
for file in acme.sh acme_3.0.sh dynamic_ip_cert.sh remote_ip_ssl.sh; do
    bash -n "$DOWNLOAD_DIR/repo/$file"
done
for file in acme.sh acme_3.0.sh dynamic_ip_cert.sh remote_ip_ssl.sh; do
    install -m 700 "$DOWNLOAD_DIR/repo/$file" "/root/$file"
done
# Inherit the caller's terminal directly; no extra pseudo-terminal is needed.
bash /root/acme_3.0.sh
