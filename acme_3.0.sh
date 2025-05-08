#!/bin/bash
set -e

# 主菜单循环
while true; do
    clear
    echo "============== SSL证书管理菜单 =============="
    echo "1）申请 SSL 证书"
    echo "2）重置环境（清除申请记录并重新部署）"
    echo "3）退出"
    echo "============================================"
    read -p "请输入选项（1-3）： " MAIN_OPTION

    case $MAIN_OPTION in
        1)
            break
            ;;
        2)
            echo "⚠️ 正在重置环境..."
            sudo rm -rf ~/.acme.sh && sudo rm -rf /tmp/acme
            echo "✅ 已清空 /tmp/acme，准备重新部署。"
            echo "📦 正在重新执行 acme.sh ..."
            sleep 1
            bash <(curl -fsSL https://raw.githubusercontent.com/slobys/SSL-Renewal/main/acme.sh)
            exit 0
            ;;
        3)
            echo "👋 已退出。"
            exit 0
            ;;
        *)
            echo "❌ 无效选项，请重新输入。"
            sleep 1
            continue
            ;;
    esac
done

# ========= 以下为 SSL 申请流程 =========

# 用户输入
read -p "请输入域名: " DOMAIN
read -p "请输入电子邮件地址: " EMAIL

# CA 选择
echo "请选择证书颁发机构（CA）："
echo "1）Let's Encrypt"
echo "2）Buypass"
echo "3）ZeroSSL"
read -p "输入选项（1-3）： " CA_OPTION
case $CA_OPTION in
    1) CA_SERVER="letsencrypt" ;;
    2) CA_SERVER="buypass" ;;
    3) CA_SERVER="zerossl" ;;
    *) echo "无效选项"; exit 1 ;;
esac

# 安装 acme.sh（如未安装）
if ! command -v acme.sh >/dev/null; then
    curl https://get.acme.sh | sh
    export PATH="$HOME/.acme.sh:$PATH"
    ~/.acme.sh/acme.sh --upgrade
fi

# 注册账户
~/.acme.sh/acme.sh --register-account -m $EMAIL --server $CA_SERVER

# 申请证书
if ! ~/.acme.sh/acme.sh --issue --standalone -d $DOMAIN --server $CA_SERVER; then
    echo "❌ 证书申请失败，已跳出。"
    exit 1
fi

# 安装证书
~/.acme.sh/acme.sh --installcert -d $DOMAIN \
    --key-file       /root/${DOMAIN}.key \
    --fullchain-file /root/${DOMAIN}.crt

# 自动续期脚本
cat << EOF > /root/renew_cert.sh
#!/bin/bash
export PATH="\$HOME/.acme.sh:\$PATH"
acme.sh --renew -d $DOMAIN --server $CA_SERVER
EOF
chmod +x /root/renew_cert.sh
(crontab -l 2>/dev/null; echo "0 0 * * * /root/renew_cert.sh > /dev/null 2>&1") | crontab -

# 提示成功
echo "✅ SSL证书申请成功！"
echo "证书路径：/root/${DOMAIN}.crt"
echo "私钥路径：/root/${DOMAIN}.key"
