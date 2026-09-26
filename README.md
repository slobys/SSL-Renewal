# SSL 一键申请

基于 `acme.sh` 的菜单式 SSL/TLS 证书管理脚本，支持域名证书、本机固定/动态公网 IP 证书，以及通过云服务器集中管理 OpenWrt/远程设备的固定或动态公网 IP SSL。

## 脚本功能

- 菜单式申请域名 SSL 证书
- 菜单式申请固定公网 IPv4 / IPv6 SSL 证书
- 固定 IP 模式自动识别 IPv4 / IPv6，支持回车选择、手动输入、重新检测和取消
- 根据本机 TCP 80 / 443 监听状态推荐验证方式，不自动停止网站或改写 Nginx
- 防火墙默认保持不变；关闭防火墙必须再次确认；申请失败不删除已有证书
- 动态公网 IP SSL：检测到公网 IP 变化后自动为新 IP 重新签发证书
- 远程 IP SSL：云服务器集中为 OpenWrt/远程设备申请、续期和部署 IP 证书
- 远程动态 IP：家庭公网 IP 变化后自动发现新 IP、重新签发并回传证书
- OpenWrt 远程模式无需安装 acme.sh / Certbot / ACME 插件
- 动态模式使用固定证书路径，公网 IP 变化后 Nginx/服务配置无需修改
- IP 证书使用 Let's Encrypt `shortlived` Profile
- IP 证书支持：
  - HTTP-01 standalone（TCP 80）
  - HTTP-01 webroot（TCP 80，适合已运行 Nginx/Apache）
  - TLS-ALPN-01（TCP 443）
- 自动安装并升级 `acme.sh`
- 自动配置 `acme.sh` 内置 cron 续期任务
- IP 短期证书使用 `--days 3` 提前续期
- 动态 IP 每 5 分钟检查一次；IP 未变化时不会重复申请
- 可配置证书更新后的服务重载命令，例如 `systemctl reload nginx`
- 可选择关闭系统防火墙、放行验证端口或保持现有防火墙配置
- 支持 Ubuntu / Debian / CentOS / RHEL / Rocky Linux / AlmaLinux / Fedora

## 主菜单

```text
============== SSL证书管理菜单 ==============
1）申请域名 SSL 证书
2）申请固定公网 IP SSL 证书
3）动态公网 IP SSL（本机IP变化自动重签）
4）本机动态 IP SSL 管理
5）远程 IP SSL（OpenWrt/远程设备）
6）重置环境（重新部署脚本）
7）退出
============================================
```

## 一键运行

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/slobys/SSL-Renewal/main/acme.sh)
```

请以 **root** 运行。再次执行同一命令即可取得新版脚本；入口只更新四个运行脚本，不删除已有证书、续期任务或设备配置，也不会把测试目录搬进 `/root`。

## 固定公网 IP 证书

固定 IP 模式适合 VPS、云服务器、固定公网 IPv4/IPv6 等场景。

### 自动识别 + 手动输入

进入主菜单 `2` 后，并行查询 IPv4 / IPv6，每种地址均有多个 HTTPS 检测源备用。检测请求设置连接/整体超时，跳过失败、空响应、错误页面和无效地址；IPv6 检测失败不会把 IPv4 一并判为失败。

```text
============== 公网 IP 选择 ==============
1）使用检测到的 IPv4：<检测结果，未检测到则不可选>
2）使用检测到的 IPv6：<检测结果，未检测到则不可选>
3）手动输入公网 IP
4）重新检测
0）取消本次申请
请选择 [默认 1]：
```

检测到 IPv4 时默认选择 IPv4；只有 IPv6 时默认选择 IPv6；两者都没有结果时默认进入手动输入。填错地址、选到不可用的地址类型时，会留在菜单中重试，不必重新启动脚本。

手动输入仅接受公网单播 IP：可自动压缩 IPv6 写法，并接受 IPv6 外层的一对方括号；拒绝私网、CGNAT 地址段、回环、链路本地、组播、保留地址，以及 URL、IPv4 的 `IP:端口`、CIDR 网段和带接口作用域的 IPv6。

**检测到的是出口地址，不等于确认该地址归本机所有，也不等于确认公网可以入站。** CGNAT 出口也可能显示一个公网地址。新检测流程会忽略 curl 的默认配置和显式代理变量，但无法绕过路由器上的透明代理、VPN 策略路由或多出口策略；请核对云控制台/路由器 WAN 地址，必要时手动填写。

本机固定 IP 菜单不会替远端自动完成验证：手动填写家里的公网 IP，仍然需要验证请求能到达本机。**云服务器替家中 OpenWrt 申请，请使用主菜单 `5` 的远程模式。** 自动识别只负责这次选地址，不会把固定模式变成动态追踪模式。

### 验证方式智能推荐

选择 IP 后，脚本先显示 TCP 80 / 443 的监听状态及能读取到的进程信息，再推荐验证方式。常规操作可以直接回车接受建议，仍可手动选择。

| 本机检测结果 | 建议 | 条件与限制 |
| --- | --- | --- |
| 80 未发现监听 | HTTP-01 临时服务 | 仍需公网 80 可达，续期时也要可用 |
| 80 由 Nginx / Apache / uHTTPd 等监听 | HTTP-01 网站目录 | 用户填写该 IP 实际对应的网站根目录，不自动猜测 |
| 80 已占用且未识别出上述服务，443 未发现监听 | TLS-ALPN-01 临时服务 | 仍需公网 443 可达，且申请/续期时能被独占 |
| 监听状态无法确定，或无法可靠判断合适方式 | 不设置默认推荐 | 重新检测，或自行配置已有网站目录 |

```text
1）HTTP-01 临时服务（80端口，需保持空闲）
2）HTTP-01 网站目录（80端口，复用已有网站，不停止服务）
3）TLS-ALPN-01 临时服务（443端口，80不可用时考虑）
4）重新检测端口
0）取消本次申请
```

选择已占用端口的临时服务模式会返回菜单，而不是自动停止 Nginx/Apache。正式申请前还会重新检查一次，以发现菜单操作期间出现的新监听。网站目录必须是存在且可写的绝对目录；脚本不会新建一个空目录并假定它已经对公网提供服务，也不会自动修改反向代理配置。

> 本机未发现监听 ≠ 防火墙已放行 ≠ 云安全组已放行 ≠ 公网验证成功。本机模式不把本地检测冒充外网连通性验证。HTTP-01 的公网入口固定为 TCP 80，TLS-ALPN-01 的公网入口为 TCP 443；最终证书不因验证方式不同而具有不同的安全等级，也不绑定这次验证端口。

证书类型、选定 IP、验证方式和网站目录会在提交前再次显示确认。防火墙选项默认“不修改”；仅需开放验证端口时可选 `2`，不会自动开启原本未开启的防火墙。选择关闭防火墙必须输入 `CLOSE` 再次确认。

重复申请时，如果 acme.sh 返回“跳过签发”，会尝试安装已有证书而不是强制重签；申请失败会保留已有证书、私钥和续期记录。安装失败仍会报错，不会误报成功。

依据：[Let's Encrypt 验证方式](https://letsencrypt.org/docs/challenge-types/)、[curl 参数说明](https://curl.se/docs/manpage.html)、[Python IP 地址校验](https://docs.python.org/3/library/ipaddress.html)。

Let's Encrypt 的 IP 地址证书必须使用 `shortlived` Profile，有效期为 160 小时（约 6 天 16 小时）。

普通固定 IP 证书会保存为：

```text
/root/你的公网IP.crt
/root/你的公网IP.key
```

IPv6 文件名中的 `:` 会自动替换为 `_`。

## 动态公网 IP SSL

动态模式适合家庭宽带等公网 IP 会变化的环境。

例如：

```text
原公网 IP：113.88.10.20
        ↓
运营商重新拨号
        ↓
新公网 IP：113.88.25.66
        ↓
脚本每 5 分钟检测
        ↓
发现 IP 变化
        ↓
为 113.88.25.66 重新申请 IP SSL
        ↓
覆盖固定证书路径
        ↓
执行服务 reload 命令
```

### 固定证书路径

动态 IPv4：

```text
/root/dynamic-ip-v4.crt
/root/dynamic-ip-v4.key
```

动态 IPv6：

```text
/root/dynamic-ip-v6.crt
/root/dynamic-ip-v6.key
```

因此 Nginx 等服务只需要永久引用固定路径，例如：

```nginx
ssl_certificate     /root/dynamic-ip-v4.crt;
ssl_certificate_key /root/dynamic-ip-v4.key;
```

以后公网 IP 变化，不需要修改 Nginx 配置。

### 动态检测逻辑

动态模式会：

1. 从多个公网 IP 检测服务获取当前 IPv4 或 IPv6；
2. 与上一次成功签发时保存的 IP 比较；
3. IP 未变化：直接退出，不重复签发；
4. IP 发生变化：为新 IP 申请新的 Let's Encrypt IP 证书；
5. 新证书成功后覆盖固定证书路径；
6. 写入新的 IP 状态；
7. 从 acme.sh 自动续期列表中移除旧 IP；
8. 如果设置了 reload 命令，则自动重载对应服务。

只有新证书成功安装后才会更新 IP 状态，因此签发失败不会破坏原有证书。

### 动态模式文件

```text
/root/.ssl-renewal/dynamic_ip_cert.sh
/root/.ssl-renewal/dynamic-ip-v4.conf
/root/.ssl-renewal/dynamic-ip-v4.state
/root/.ssl-renewal/dynamic-ip-v4.log
```

IPv6 使用对应的 `v6` 文件。

### 动态 IP 管理菜单

```text
============== 动态 IP SSL 管理 ==============
1）查看状态
2）立即检查/更新 IPv4
3）立即检查/更新 IPv6
4）删除 IPv4 自动检测
5）删除 IPv6 自动检测
6）返回主菜单
==============================================
```

删除自动检测时，已经签发到 `/root/dynamic-ip-v4.crt` / `.key` 或 IPv6 对应路径的证书会保留，不会自动删除。

## 远程 IP SSL（OpenWrt / 远程设备）

远程模式把云服务器作为“证书控制中心”。ACME 客户端运行在云服务器，家庭 OpenWrt 只负责 SSH 管理、临时转发 HTTP-01 验证流量、接收证书并重启对应服务，因此 OpenWrt 不需要安装 acme.sh、Certbot 或额外 ACME 插件。

远程管理菜单：

~~~text
============ 远程 IP SSL ============
1）添加远程设备
2）固定公网 IP
3）动态公网 IP
4）立即申请/更新证书
5）查看设备状态
6）删除设备
7）返回
======================================
~~~

### 远程验证链路

正式申请前，脚本会先建立与真实 ACME 验证相同的临时链路并进行公网自检：

~~~text
Let's Encrypt / 公网自检请求
        ↓
家庭公网 IP:80
        ↓
OpenWrt 临时 nftables/iptables REDIRECT
        ↓
OpenWrt 临时高位端口
        ↓
SSH Reverse Tunnel
        ↓
云服务器 localhost 高位端口
        ↓
acme.sh standalone
~~~

验证完成后会删除 OpenWrt 临时防火墙规则并关闭 SSH Reverse Tunnel，不长期占用这一条验证转发。

如果家庭公网 IP 在上级光猫/主路由上，需要预先把公网 TCP 80 转发到 OpenWrt；如果存在 CGNAT、运营商禁止 TCP 80 入站或没有真正可入站的公网地址，自检会失败并停止正式申请。

### 添加远程设备

添加设备时需要填写：

~~~text
设备名称 / 设备ID
SSH 管理地址
SSH 端口
SSH 用户
Let's Encrypt 邮箱
远端证书路径
远端私钥路径
证书更新后的 reload 命令
~~~

动态家庭公网 IP 场景强烈建议 SSH 管理地址使用 ZeroTier、Tailscale、WireGuard 等稳定私网地址，而不是家庭公网 IP。这样公网 IP 改变后，云服务器仍然能够找到 OpenWrt。

自动任务必须使用 SSH 密钥。脚本会检查 /root/.ssh/id_ed25519，没有时自动生成；如果远端还没有安装公钥，可以调用 ssh-copy-id 完成首次配置。

检测到 OpenWrt 时，脚本会检查 Dropbear GatewayPorts。远程反向转发需要它允许远程转发端口绑定到非 loopback 地址；如果未启用，脚本会设置 GatewayPorts=1、提交配置、重启 Dropbear，并再次检查 SSH。

OpenWrt 默认部署路径：

~~~text
证书：/etc/uhttpd.crt
私钥：/etc/uhttpd.key
重载：/etc/init.d/uhttpd restart
~~~

也可以改成 Nginx、HAProxy 等服务自己的路径和 reload 命令。

### 远程固定公网 IP

逻辑：

~~~text
选择远程设备
    ↓
输入固定公网 IP
    ↓
SSH 检查 OpenWrt
    ↓
建立临时 HTTP-01 验证隧道
    ↓
公网自检通过
    ↓
Let's Encrypt 验证家庭公网 IP
    ↓
云服务器取得证书和私钥
    ↓
SSH 上传到远端临时文件
    ↓
备份旧证书
    ↓
原子替换 crt/key
    ↓
执行 reload
    ↓
成功后记录状态
~~~

固定 IP 模式每 6 小时检查一次是否进入续期窗口。未到续期时间时 acme.sh 会跳过，不会重复签发。

### 远程动态公网 IP

逻辑：

~~~text
云服务器
   ↓ ZeroTier / 稳定 SSH
OpenWrt
   ↓
查询 OpenWrt 当前公网 IP
   ↓
与上次成功签发的 IP 比较
   ↓
 ┌─ IP 相同
 │     ↓
 │  不重新申请
 │  到正常续期检查时间才检查证书
 │
 └─ IP 变化
       ↓
    为新 IP 建立临时验证链路
       ↓
    公网 TCP 80 自检
       ↓
    为新 IP 申请证书
       ↓
    SSH 部署回 OpenWrt
       ↓
    reload 服务
       ↓
    成功后保存新 IP
       ↓
    移除旧 IP 的 acme.sh 续期记录
~~~

动态模式每 5 分钟检查一次 IP，但 IP 没变化时不会每 5 分钟申请证书；正常证书续期检查会限制在约 6 小时一次。

### 立即申请 / 更新证书

提供：

~~~text
1）正常检查
2）强制重新签发
~~~

正常检查会自动判断 IP 是否变化和证书是否进入续期窗口。强制重新签发会消耗 CA 请求额度，因此需要再次确认。

### 远程证书部署保护

新证书不会直接粗暴覆盖。脚本先上传为临时文件，备份当前证书和私钥，再进行替换并执行 reload。

如果 reload 失败：

~~~text
恢复旧证书 / 私钥
      ↓
尝试恢复原服务
      ↓
本次部署返回失败
~~~

只有证书签发、远端部署和 reload 都成功后，才更新“当前管理 IP”和成功状态。

如果新 IP 的证书已经成功签发，但远端部署曾失败，后续运行允许复用 acme.sh 中已有的有效证书继续尝试部署，避免无意义地反复向 CA 重签。

### 查看状态与删除设备

状态页会显示设备、SSH 地址、固定/动态模式、当前证书对应 IP、证书路径、最后成功/检查/错误时间、证书到期时间、cron 状态，以及动态模式实时公网 IP。

删除设备会删除云服务器上的设备配置、状态、自动任务和该设备本地证书副本，并移除对应 acme.sh 管理记录；不会主动删除 OpenWrt 当前正在使用的证书和私钥，避免删除管理配置时直接造成 HTTPS 中断。

### 远程模式文件

运行后主要保存在：

~~~text
/root/.ssl-renewal/remote/
├── remote_ip_ssl.sh
├── devices/
│   ├── <device>.conf
│   └── <device>.state
├── certs/
│   └── <device>/
│       ├── fullchain.crt
│       └── private.key
└── logs/
    └── <device>.log
~~~

远程集中管理模式下，云服务器会持有证书私钥，因此应重点保护 /root/.ssh 和 /root/.ssl-renewal 的权限。

## IP 验证方式

| 验证方式 | 公网端口 | 适用场景 |
| --- | --- | --- |
| HTTP-01 standalone | TCP 80 | 80 端口长期空闲 |
| HTTP-01 webroot | TCP 80 | 已运行 Nginx / Apache，动态模式推荐 |
| TLS-ALPN-01 | TCP 443 | 80 无法使用且 443 可被 ACME 客户端独占 |

> standalone / TLS-ALPN 验证时，对应端口必须空闲。动态模式下如果 Nginx 长期占用 80，建议使用 webroot。

## 家庭公网 IP 使用注意

家庭网络如果在路由器后面，申请证书时仅“检测到公网 IP”还不够。

还需要保证：

```text
互联网
  ↓
家庭公网 IP
  ↓
路由器 TCP 80 或 443 端口转发
  ↓
运行 SSL-Renewal/acme.sh 的设备
```

脚本能够处理本机 UFW/firewalld，但无法自动替你配置家庭路由器的 NAT 端口映射。

如果运营商使用 CGNAT（例如没有真正可入站的公网 IPv4），即使能检测到一个出口 IP，也无法通过 HTTP-01/TLS-ALPN-01 完成公网验证。

## 公网 IP 检测

动态模式会依次尝试多个检测源，并验证结果必须是可公开路由的公网地址。

IPv4 包括：

- 4.ipw.cn
- api4.ipify.org
- ipv4.icanhazip.com

IPv6 使用对应的 IPv6 检测地址。

只在检测到公网 IP 发生变化时重新签发，不会每 5 分钟向 Let's Encrypt 申请证书。

## 离线回归测试

```bash
python3 tests/test_smart_menu.py
```

测试覆盖自动 IPv4 / IPv6、单栈和检测失败兜底、手动校验、检测源失败切换、代理参数、端口占用推荐、未知状态、网站目录、取消操作、防火墙默认值、重复申请与失败保护。测试通过替身命令隔离网络和系统操作，不请求真实证书、不连接你的软路由，也不修改测试机的防火墙或服务。

新增交互已经过离线测试；这不代表你的公网入站、真实 CA 签发和远程 OpenWrt 链路已完成实机验收。本次优化不改变既有远程验证架构，也没有新增 DDNS 更新功能。

## 注意事项

- IP 证书只能申请公网可路由 IP，不能申请 `192.168.x.x`、`10.x.x.x`、`172.16-31.x.x`、Loopback、链路本地、CGNAT 或其他保留地址。
- 如果是云服务器，请同时检查云厂商安全组。
- 如果是家庭网络，请确认路由器端口映射和运营商入站限制。
- 远程 OpenWrt 模式目前使用 HTTP-01 / TCP 80 完成公网 IP 控制权验证。
- 远程动态模式推荐使用 ZeroTier 等稳定管理链路，否则家庭公网 IP 改变后云服务器可能无法再 SSH 到设备。
- 远程模式下云服务器持有并分发私钥，需要保护云服务器 root、SSH 密钥及 /root/.ssl-renewal。
- IP 地址证书固定使用 Let's Encrypt。
- 不要在验证失败时连续高频手工重复申请，先检查公网 IP、端口、防火墙、NAT 和安全组。
- 动态 IP SSL 解决的是“IP 变化后证书自动重签”，它不会自动把新 IP 告诉远程客户端；如果还需要通过固定名称找到家庭网络，可以另外使用 DDNS。

