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

# ========= 确保 acme_3.0.sh 存在 =========
if [ ! -f /tmp/acme/acme_3.0.sh ]; then
    echo "❌ 错误：/tmp/acme/acme_3.0.sh 文件不存在，克隆失败或仓库缺失该文件。"
    exit 1
fi

# ========= 提醒可能覆盖 =========
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

# ========= 检查执行是否成功 =========
if [ $? -eq 0 ]; then
    echo "✅ acme_3.0.sh 执行完成。"
else
    echo "❌ acme_3.0.sh 执行失败，请检查脚本内容或权限。"
fi
