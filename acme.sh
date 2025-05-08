#!/bin/bash
set -e

# 清理旧目录
rm -rf /tmp/acme

# 克隆仓库
git clone https://github.com/slobys/SSL-Renewal.git /tmp/acme

# 移动所有文件到 /root
mv /tmp/acme/* /root

# 添加执行权限
chmod +x /root/acme_3.0.sh

# 在伪终端中执行
script -q -c "/root/acme_3.0.sh" /dev/null
