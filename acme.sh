#!/bin/bash

# 遇到错误立即退出
set -e

# ========= 自动清理旧目录 =========
if [ -d /tmp/acme ]; then
    echo "🧹 检测到旧的 /tmp/acme 目录，正在删除..."
    rm -rf /tmp/acme
fi

# ========= 克隆 GitHub 仓库 =========
echo "📥 正在克隆 acme_3.0 脚本仓库..."
git clone https://github.com/slobys/SSL-Renewal.git /tmp/acme

# ========= 检查 acme_3.0.sh 是否存在于克隆目录 =========
if [ ! -f /tmp/acme/acme_3.0.sh ]; then
    echo "❌ 错误：未在仓库中找到 acme_3.0.sh 文件，请确认仓库内容正确。"
    exit 1
fi

# ========= 检查目标文件是否已存在 =========
if [ -f /root/acme_3.0.sh ]; then
    read -p "⚠️ 检测到 /root/acme_3.0.sh 已存在，是否覆盖？(y/n): " confirm
    if [[ "$confirm" != "y" ]]; then
        echo "🚫 已取消操作，未覆盖现有脚本。"
        exit 1
    fi
fi

# ========= 移动脚本到 /root =========
echo "📦 正在移动脚本文件到 /root..."
mv /tmp/acme/* /root

# ========= 设置执行权限 =========
chmod +x /root/acme_3.0.sh

# ========= 执行主脚本（通过虚拟终端） =========
echo "🚀 正在以终端方式执行 /root/acme_3.0.sh ..."
if [ -f /root/acme_3.0.sh ]; then
    # 使用 script 模拟交互式终端运行
    script -q -c "/root/acme_3.0.sh" /dev/null
    echo "✅ acme_3.0.sh 已成功执行。"
else
    echo "❌ 找不到 /root/acme_3.0.sh 文件，请检查是否移动成功。"
    exit 1
fi
