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

# ========= 提醒用户将覆盖已有文件（如果有） =========
if [ -f /root/acme_3.0.sh ]; then
    echo "⚠️ 警告：/root/acme_3.0.sh 已存在，将被覆盖。"
fi

# ========= 移动脚本到 /root =========
echo "📦 正在移动脚本文件到 /root..."
mv /tmp/acme/* /root

# ========= 添加执行权限 =========
chmod +x /root/acme_3.0.sh

# ========= 执行主脚本 =========
echo "🚀 正在执行 /root/acme_3.0.sh ..."
bash /root/acme_3.0.sh
