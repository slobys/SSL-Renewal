# SSL 一键申请

菜单式证书工具：Linux 服务器域名 / IP 证书，以及 **OpenWrt 软路由本机申请、动态 IP 重签和自动续期**。

## 一键运行

**OpenWrt / iStoreOS：直接在软路由 SSH 终端以 root 执行。** 自动进入本机模式，不需要云服务器、SSH 回传、Bash、Python 或 Git。

```sh
wget -O /tmp/ssl-renewal-install.sh https://raw.githubusercontent.com/slobys/SSL-Renewal/main/acme.sh && sh /tmp/ssl-renewal-install.sh
```

下载失败时检查网络与 CA 根证书；也可用 `curl -fsSL URL -o /tmp/ssl-renewal-install.sh`。不要关闭 TLS 校验。

**Ubuntu / Debian / CentOS / RHEL 等服务器：** 原命令保持可用。

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/slobys/SSL-Renewal/main/acme.sh)
```

再次执行更新脚本，保留证书和配置。旧远程模式退出主菜单，已有远程任务不会自动迁移或删除。

## 主菜单

| 入口 | 用途 |
| --- | --- |
| 1）域名证书 | Linux 本机申请 |
| 2）本机固定 IP 证书 | 云服务器常用；自动识别 / 手动输入 |
| 3）本机动态 IP 证书 | Linux 环境的开通与管理 |
| 4）OpenWrt 本机模式 | **软路由自己申请、保存和续期**；必须在软路由运行 |
| 5）更新 / 重新部署脚本 | 保留证书和配置 |
| 6）退出 | 结束运行 |

## OpenWrt 怎么用

选择 **开通 / 重新配置 → IPv4 或 IPv6 → 动态公网 IP**，填写邮箱；接口通常为 `wan` / `wan6`。自动检测取 WAN 接口地址；光猫路由时可改选出口检测，固定模式支持手动 IP。

验证选择 **HTTP-01（公网 TCP80）** 或 **TLS-ALPN-01（公网 TCP443）**。脚本只在验证期间把选定 WAN 入口转到本机专用端口，不停止 LuCI、不关闭防火墙、不修改 Dropbear；该公网端口的普通访问会短暂中断。

证书用途可选 **仅保存文件** 或 **应用到 uHTTPd/LuCI**。后者会备份配置、更新证书路径并重启 uHTTPd；重载失败尝试回滚。其他服务可填写自己的重载命令。

每 5 分钟检查：**IP 变化就重签；IP 未变但证书剩余不足 3 天也会续签。** 校验信任链、IP 和私钥后才部署；失败退避重试，保留旧证书。无需额外 LuCI 插件，依赖通过 `opkg/apk` 安装。

管理菜单提供状态、立即检查、停用 / 恢复。**OpenWrt 停用会同时停止重签和续签**，保留文件但证书会自然过期；这与 Linux 第 3 项仅停用 IP 变化检测不同。

## 证书与日志

| 模式 | 路径 |
| --- | --- |
| Linux 域名 / 固定 IP | `/root/<域名或IP>.crt`、`.key`（IPv6 冒号换成下划线） |
| Linux 动态 IP | `/root/dynamic-ip-v4.crt`、`.key`；IPv6 用 `v6` |
| OpenWrt IPv4 | `/etc/ssl-renewal/openwrt/certs/v4/current/fullchain.pem`、`privkey.pem` |
| OpenWrt IPv6 | 上述路径中的 `v4` 改为 `v6` |

软路由配置和私钥留在本机；日志：`logread -e ssl-renewal-openwrt`。不要给同一 uHTTPd 实例配置两张不同地址族的单 IP 证书互相覆盖。

## 必要提醒

- Let's Encrypt IP 证书有效期 **160 小时**，自动管理期间需保持验证条件。上级光猫 NAT、CGNAT、运营商端口限制无法靠证书解决。
- 公网 IP 证书只匹配该 IP；用 `192.168.x.x`、ZeroTier 地址或域名访问不会自动匹配。不要为了验证把整个 LuCI 开放到公网。
- IPv6 需使用路由器实际持有的全局地址，不是委派前缀。出口检测仍可能受透明代理影响。本项目不更新 DDNS，也不通知客户端新 IP。
- 自动防火墙适配 fw4/nftables 与 fw3/iptables；定制固件仍需实机验证。升级固件前自行备份证书和配置。

离线回归：`python3 -m unittest discover -s tests -q`。测试使用模拟 OpenWrt 命令和临时测试 CA；不代表真实公网入站或生产 CA 签发已经验证。

协议依据：[Let's Encrypt 验证方式](https://letsencrypt.org/docs/challenge-types/) · [证书 Profile](https://letsencrypt.org/docs/profiles/) · [acme.sh](https://github.com/acmesh-official/acme.sh)
