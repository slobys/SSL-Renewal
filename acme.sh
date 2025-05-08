#!/bin/bash
set -e

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
        sudo apt update -y
        sudo apt install git -y || {
            echo "❌ git 安装失败，请先手动运行以下命令："
            echo "sudo apt update -y && sudo apt install git -y"
            exit 1
        }
    elif [[ "$OS_ID" == "centos" ]]; then
        sudo yum update -y
        sudo yum install git -y || {
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

# ========= 清理旧目录并继续 =========
rm -rf /tmp/acme
git clone https://github.com/slobys/SSL-Renewal.git /tmp/acme
mv /tmp/acme/* /root
chmod +x /root/acme_3.0.sh
script -q -c "/root/acme_3.0.sh" /dev/null
