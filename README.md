# SSL 一键申请

菜单式证书工具：Linux 服务器域名 / IP 证书，以及 **OpenWrt 软路由本机申请、动态 IP 重签和自动续期**。

## 一键运行

**服务器与 OpenWrt / iStoreOS 保留同一条安装命令，在目标设备的 SSH 终端以 root 执行：**

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/slobys/SSL-Renewal/main/acme.sh)
```

系统识别与安装分流均在 `acme.sh` 内完成：Linux 服务器进入服务器菜单；OpenWrt / iStoreOS 请直接在软路由运行，自动进入本机菜单，无需云服务器代办。

**入口前置条件：**设备需已有 `bash`、`curl`。OpenWrt 缺少时先通过 `opkg` / `apk` 安装；当前 Shell 不支持 `<(...)` 时，先输入 `bash` 再执行。软路由管理主体仍使用 `ash`，不需要 Python 或 Git；尚未启动的脚本不能补装入口自身缺少的命令。

再次执行可更新脚本，保留证书和配置；已有远程任务不自动迁移或删除。

## 主菜单

| 入口 | 用途 |
| --- | --- |
| 1）域名证书 | Linux 本机申请 |
| 2）本机固定 IP 证书 | 云服务器常用；自动识别 / 手动输入 |
| 3）OpenWrt 本机模式 | **软路由自己申请、保存和续期**；必须在软路由运行 |
| 4）更新 / 重新部署脚本 | 保留证书和配置 |
| 5）退出 | 结束运行 |
| 6）卸载服务器端 | 保留证书卸载，或备份后清理本项目配置 |

服务器本机动态 IP 入口暂时移除，已有证书、配置和自动任务保留；**OpenWrt 动态 IP 功能不受影响**。

## OpenWrt 怎么用

选择 **申请 / 重新配置 → IPv4 或 IPv6 → 动态公网 IP**，填写邮箱；接口通常为 `wan` / `wan6`。自动检测取 WAN 接口地址；光猫路由时可改选出口检测，固定模式支持手动 IP。

验证选择 **HTTP-01（公网 TCP80）** 或 **TLS-ALPN-01（公网 TCP443）**。脚本只在验证期间把选定 WAN 入口转到本机专用端口，不停止 LuCI、不关闭防火墙、不修改 Dropbear；该公网端口的普通访问会短暂中断。

证书用途可选 **仅保存文件** 或 **应用到 uHTTPd/LuCI**。后者会备份配置、更新证书路径并重启 uHTTPd；重载失败尝试回滚。其他服务可填写自己的重载命令。

每 5 分钟检查：**IP 变化就重签；IP 未变但证书剩余不足 3 天也会续签。** 校验信任链、IP 和私钥后才部署；失败退避重试，保留旧证书。无需额外 LuCI 插件，依赖通过 `opkg/apk` 安装。

管理菜单提供状态、立即检查、停用 / 恢复。**OpenWrt 停用会同时停止重签和续签**，保留文件但证书会自然过期。

## 证书与日志

| 模式 | 路径 |
| --- | --- |
| Linux 域名 / 固定 IP | `/root/<域名或IP>.crt`、`.key`（IPv6 冒号换成下划线） |
| 旧版 Linux 动态 IP（保留） | `/root/dynamic-ip-v4.crt`、`.key`；IPv6 用 `v6` |
| OpenWrt IPv4 | `/etc/ssl-renewal/openwrt/certs/v4/current/fullchain.pem`、`privkey.pem` |
| OpenWrt IPv6 | 上述路径中的 `v4` 改为 `v6` |

软路由配置和私钥留在本机；日志：`logread -e ssl-renewal-openwrt`。不要给同一 uHTTPd 实例配置两张不同地址族的单 IP 证书互相覆盖。

## 卸载 / 重装

**服务器选主菜单 6；软路由选本机菜单 5。** 回车默认保留证书与配置，输入 `UNINSTALL` 才执行；清理模式需输入 `PURGE`，两种方式都会先备份到 `/root/ssl-renewal-backups/`。

服务器卸载只移除本项目脚本、动态/旧远程任务；清理模式再删除对应配置和日志。**服务器证书、共享 `~/.acme.sh` 及其续期任务保留**，不会猜测删除旧版证书，也不连接远端设备。

OpenWrt 卸载会停止重签和续签；清理模式会删除本项目专用数据，若 LuCI 正在引用证书，先改为读取备份证书并重启 uHTTPd，失败则中止清理。其他服务引用需先自行迁移。备份证书同样会自然过期。

不卸载系统依赖，不关闭防火墙/cron，不改 SSH；正在签发时不强杀任务。重装执行原命令，保留配置的软路由需从菜单恢复自动管理；备份含私钥，请妥善保管。

## 必要提醒

- Let's Encrypt IP 证书有效期 **160 小时**，自动管理期间需保持验证条件。上级光猫 NAT、CGNAT、运营商端口限制无法靠证书解决。
- 公网 IP 证书只匹配该 IP；用 `192.168.x.x`、ZeroTier 地址或域名访问不会自动匹配。不要为了验证把整个 LuCI 开放到公网。
- IPv6 需使用路由器实际持有的全局地址，不是委派前缀。出口检测仍可能受透明代理影响。本项目不更新 DDNS，也不通知客户端新 IP。
- 自动防火墙适配 fw4/nftables 与 fw3/iptables；定制固件仍需实机验证。升级固件前自行备份证书和配置。

离线回归：`python3 -m unittest discover -s tests -q`。测试使用模拟 OpenWrt 命令和临时测试 CA；不代表真实公网入站或生产 CA 签发已经验证。

协议依据：[Let's Encrypt 验证方式](https://letsencrypt.org/docs/challenge-types/) · [证书 Profile](https://letsencrypt.org/docs/profiles/) · [acme.sh](https://github.com/acmesh-official/acme.sh)
