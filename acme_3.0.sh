#!/bin/bash

set -e

# ✅ 开始前自动清理 /tmp/acme（避免 git clone 或其他冲突）
[ -d /tmp/acme ] && rm -rf /tmp/acme

# 主菜单循环
while true; do
    echo ""
    echo "============== SSL证书管理菜单 =============="
    echo "1) 申请SSL证书"
    echo "2) 移除申请证书时所生成的文件（彻底清除）"
    echo "3) 退出"
    echo "============================================"
    read -p "请输入选项 (1-3): " MAIN_OPTION

    case $MAIN_OPTION in
        1)
            break
            ;;
        2)
            read -p "请输入要移除证书的域名: " DOMAIN_TO_REMOVE
            read -p "⚠️ 确认删除 ${DOMAIN_TO_REMOVE} 的所有证书配置？(y/n): " confirm
            if [[ "$confirm" != "y" ]]; then
                echo "已取消操作。"
                continue
            fi

            # 删除证书文件、续期脚本和 acme.sh 配置目录
            rm -f /root/${DOMAIN_TO_REMOVE}.key \
                  /root/${DOMAIN_TO_REMOVE}.crt \
                  /root/renew_cert.sh
            rm -rf ~/.acme.sh/${DOMAIN_TO_REMOVE}

            echo "✅ 已彻底移除 ${DOMAIN_TO_REMOVE} 的所有证书相关文件。"
            continue
            ;;
        3)
            echo "👋 已退出。"
            exit 0
            ;;
        *)
            echo "❌ 无效选项，请重新输入。"
            continue
            ;;
    esac
done

# 检查系统类型
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
elif command -v lsb_release >/dev/null 2>&1; then
    OS=$(lsb_release -si | tr '[:upper:]' '[:lower:]')
else
    echo "无法确定操作系统类型，请手动安装依赖项。"
    exit 1
fi

# 用户输入
read -p "请输入域名: " DOMAIN
read -p "请输入电子邮件地址: " EMAIL

# 若已存在证书文件，提醒用户
if [ -f "/root/${DOMAIN}.key" ] || [ -f "/root/${DOMAIN}.crt" ]; then
    echo "⚠️ 检测到已存在的证书文件：/root/${DOMAIN}.key 或 /root/${DOMAIN}.crt"
    echo "如需重新申请，请先选择菜单中的“移除证书文件”操作。"
    exit 1
fi

# CA选择
echo "请选择要使用的证书颁发机构 (CA):"
echo "1) Let's Encrypt"
echo "2) Buypass"
echo "3) ZeroSSL"
read -p "输入选项 (1, 2, or 3): " CA_OPTION

case $CA_OPTION in
    1) CA_SERVER="letsencrypt" ;;
    2) CA_SERVER="buypass" ;;
    3) CA_SERVER="zerossl" ;;
    *) echo "无效选项"; exit 1 ;;
esac

# 防火墙选择
echo "是否关闭防火墙？"
echo "1) 是"
echo "2) 否"
read -p "输入选项 (1 或 2): " FIREWALL_OPTION

if [ "$FIREWALL_OPTION" -eq 2 ]; then
    echo "是否放行特定端口？"
    echo "1) 是"
    echo "2) 否"
    read -p "输入选项 (1 或 2): " PORT_OPTION
    if [ "$PORT_OPTION" -eq 1 ]; then
        read -p "请输入要放行的端口号: " PORT
    fi
fi

# 安装依赖、关闭防火墙或放行端口
case $OS in
    ubuntu|debian)
        sudo apt update
        sudo apt upgrade -y
        sudo apt install -y curl socat git cron
        if [ "$FIREWALL_OPTION" -eq 1 ]; then
            command -v ufw >/dev/null && sudo ufw disable || echo "UFW 未安装"
        elif [ "$PORT_OPTION" -eq 1 ]; then
            command -v ufw >/dev/null && sudo ufw allow $PORT || echo "UFW 未安装"
        fi
        ;;
    centos)
        sudo yum update -y
        sudo yum install -y curl socat git cronie
        sudo systemctl start crond && sudo systemctl enable crond
        if [ "$FIREWALL_OPTION" -eq 1 ]; then
            sudo systemctl stop firewalld && sudo systemctl disable firewalld
        elif [ "$PORT_OPTION" -eq 1 ]; then
            sudo firewall-cmd --permanent --add-port=${PORT}/tcp
            sudo firewall-cmd --reload
        fi
        ;;
    *) echo "不支持的操作系统：$OS"; exit 1 ;;
esac

# 安装 acme.sh
curl https://get.acme.sh | sh
export PATH="$HOME/.acme.sh:$PATH"
/root/.acme.sh/acme.sh --upgrade
chmod +x "$HOME/.acme.sh/acme.sh"

# 注册账户
acme.sh --register-account -m $EMAIL --server $CA_SERVER

# 申请证书（无需 --force，因为清理已完成）
if ! ~/.acme.sh/acme.sh --issue --standalone -d $DOMAIN --server $CA_SERVER; then
    echo "❌ 证书申请失败，清理文件。"
    rm -f /root/${DOMAIN}.key /root/${DOMAIN}.crt
    ~/.acme.sh/acme.sh --remove -d $DOMAIN
    rm -rf ~/.acme.sh/${DOMAIN}
    exit 1
fi

# 安装证书
~/.acme.sh/acme.sh --installcert -d $DOMAIN \
    --key-file       /root/${DOMAIN}.key \
    --fullchain-file /root/${DOMAIN}.crt

# 提示成功
echo "✅ SSL证书已生成："
echo "证书: /root/${DOMAIN}.crt"
echo "私钥: /root/${DOMAIN}.key"

# 自动续期脚本
cat << EOF > /root/renew_cert.sh
#!/bin/bash
export PATH="\$HOME/.acme.sh:\$PATH"
acme.sh --renew -d $DOMAIN --server $CA_SERVER
EOF
chmod +x /root/renew_cert.sh
(crontab -l 2>/dev/null; echo "0 0 * * * /root/renew_cert.sh > /dev/null 2>&1") | crontab -
