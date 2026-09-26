#!/bin/sh
# OpenWrt local IP certificates. BusyBox ash/dash; no Bash, Python or SSH needed.
# Runtime state lives in RAM; accounts/certificates persist in the private base.
OW_BASE=${SSL_RENEWAL_OPENWRT_BASE:-/etc/ssl-renewal/openwrt}
OW_RUN=${SSL_RENEWAL_OPENWRT_RUN:-/tmp/ssl-renewal-openwrt}
OW_SELF=${SSL_RENEWAL_OPENWRT_SELF:-/root/.ssl-renewal/openwrt/openwrt_ip_ssl.sh}
OW_ACME=${SSL_RENEWAL_OPENWRT_ACME:-$OW_BASE/client/acme.sh}
OW_CRONTAB=${SSL_RENEWAL_OPENWRT_CRONTAB:-/etc/crontabs/root}
OW_INIT=${SSL_RENEWAL_OPENWRT_INIT:-/etc/init.d}
OW_BACKUPS=${SSL_RENEWAL_OPENWRT_BACKUPS:-/root/ssl-renewal-backups}
OW_MARKER='# ssl-renewal-openwrt-local'
OW_WATCH_PID=''
OW_FW_TAG=''
OW_FW_KIND=''
OW_STAGE=''

ow_log() {
    printf '%s [OpenWrt IP SSL] %s\n' "$(date '+%F %T')" "$*"
    if command -v logger >/dev/null 2>&1; then logger -t ssl-renewal-openwrt "$*" || true; fi
}
ow_die() { ow_log "错误：$*"; exit 1; }
ow_require() {
    [ "$(id -u)" = 0 ] || ow_die '请用 root 运行。'
    [ -f /etc/openwrt_release ] || ow_die '此模式必须在 OpenWrt / iStoreOS 本机运行，不会连接远程设备。'
}
# Runs before dependency installation. Minimal OpenWrt may omit the stat applet;
# BusyBox ls -ldn provides a numeric owner without adding a package dependency.
# Read metadata for the directory itself, not its contents or a symlink target.
ow_dir_owner_uid() (
    [ -d "$1" ] && [ ! -L "$1" ] || exit 1
    details=$(LC_ALL=C ls -ldn -- "$1" 2>/dev/null) || exit 1
    printf '%s\n' "$details" | awk '
        NR == 1 && $1 ~ /^d/ && $3 ~ /^[0-9]+$/ {print $3; valid=1; exit}
        END {if (!valid) exit 1}'
)
ow_dirs() {
    umask 077
    [ ! -L "$OW_BASE" ] && [ ! -L "$OW_RUN" ] || ow_die '管理目录不能是符号链接。'
    mkdir -p "$OW_BASE" "$OW_RUN" || ow_die '无法创建管理目录，请检查存储空间和写入权限。'
    ow_current_uid=$(id -u) || ow_die '无法读取当前用户 UID。'
    case "$ow_current_uid" in ''|*[!0-9]*) ow_die '无法读取当前用户 UID。';; esac
    for ow_directory in "$OW_BASE" "$OW_RUN"; do
        ow_directory_uid=$(ow_dir_owner_uid "$ow_directory") ||
            ow_die "无法读取管理目录所有者（请检查 ls -ldn 是否可用）：$ow_directory"
        [ "$ow_directory_uid" = "$ow_current_uid" ] ||
            ow_die "管理目录所有者不正确：$ow_directory"
    done
    chmod 700 "$OW_BASE" "$OW_RUN" || ow_die '无法设置管理目录权限。'
}
ow_family() { case "$1" in 4|6) ;; *) ow_die '地址类型只能是 4 或 6。';; esac; }
ow_paths() {
    ow_family "$1"
    FAMILY=$1
    CONF="$OW_BASE/v$FAMILY.conf"
    STATE="$OW_BASE/v$FAMILY.ip"
    RECEIPT="$OW_BASE/v$FAMILY.deployed"
    DISABLED="$OW_BASE/v$FAMILY.disabled"
    CERTROOT="$OW_BASE/certs/v$FAMILY"
    PENDING="$OW_BASE/pending/v$FAMILY"
    ACME_CONFIG="$OW_BASE/acme/v$FAMILY"
    RETRY="$OW_RUN/v$FAMILY.retry"
}
ow_lock() {
    command -v flock >/dev/null 2>&1 || ow_die '缺少 flock，请先在菜单中完成开通。'
    exec 9>"$OW_RUN/operation.lock"
    if ! flock -n 9; then ow_log '已有证书操作在运行，本次不重复执行。'; exit 0; fi
}

# Conservative public-unicast validation and canonicalization using BusyBox awk.
# Special-use, documentation, multicast, scoped/mapped and transition IPs fail closed.
ow_ip() {
    printf '%s\n' "$1" | awk -v family="$2" -v public="${3:-1}" '
    function hex(s, n,i,c) { n=0; for(i=1;i<=length(s);i++){c=index("0123456789abcdef",substr(s,i,1))-1;if(c<0)return -1;n=n*16+c} return n }
    { raw=$0; if(NR>1) bad=1 }
    END {
      if(bad || NR!=1) exit 1
      gsub(/^[ \t]+|[ \t\r]+$/, "", raw)
      if(family==4) {
        n=split(raw,a,"."); if(n!=4) exit 1
        for(i=1;i<=4;i++) {if(a[i]!~/^[0-9]+$/ || length(a[i])>3 || a[i]+0>255 || (length(a[i])>1 && substr(a[i],1,1)=="0"))exit 1;a[i]+=0}
        if(public && (a[1]==0 || a[1]==10 || a[1]==127 || a[1]>=224 ||
          (a[1]==100 && a[2]>=64 && a[2]<=127) || (a[1]==169 && a[2]==254) ||
          (a[1]==172 && a[2]>=16 && a[2]<=31) || (a[1]==192 && a[2]==168) ||
          (a[1]==192 && a[2]==0 && (a[3]==0 || a[3]==2)) ||
          (a[1]==192 && a[2]==88 && a[3]==99) || (a[1]==198 && (a[2]==18 || a[2]==19)) ||
          (a[1]==198 && a[2]==51 && a[3]==100) || (a[1]==203 && a[2]==0 && a[3]==113))) exit 1
        printf "%d.%d.%d.%d\n",a[1],a[2],a[3],a[4]; exit 0
      }
      if(family!=6) exit 1
      if(substr(raw,1,1)=="[" && substr(raw,length(raw),1)=="]")raw=substr(raw,2,length(raw)-2)
      raw=tolower(raw); if(raw!~/^[0-9a-f:]+$/ || raw~/:::/)exit 1
      p=index(raw,"::")
      if(p) {
        left=substr(raw,1,p-1);right=substr(raw,p+2)
        if(index(right,"::"))exit 1
        nl=left==""?0:split(left,l,":"); nr=right==""?0:split(right,r,":")
        if(nl+nr>=8)exit 1
        for(i=1;i<=nl;i++)a[i]=l[i]
        for(i=nl+1;i<=8-nr;i++)a[i]="0"
        for(i=1;i<=nr;i++)a[8-nr+i]=r[i]
      } else if(split(raw,a,":")!=8)exit 1
      for(i=1;i<=8;i++){if(length(a[i])<1 || length(a[i])>4 || a[i]!~/^[0-9a-f]+$/)exit 1;a[i]=hex(a[i])}
      if(public && (a[1]<8192 || a[1]>16383 || a[1]==8194 ||
         (a[1]==8193 && (a[2]<512 || a[2]==3512)) || a[1]==16383)) exit 1
      best=0;len=0
      for(i=1;i<=8;i++){if(a[i]==0){s=i;while(i<=8 && a[i]==0)i++;if(i-s>len){best=s;len=i-s}}}
      out="";i=1
      while(i<=8){if(len>=2 && i==best){out=out "::";i+=len;continue}
        if(out!="" && substr(out,length(out),1)!=":")out=out ":"
        out=out sprintf("%x",a[i]);i++}
      print out
    }'
}
ow_name() { case "$1" in ''|*[!a-zA-Z0-9_.-]*) return 1;; *) return 0;; esac; }
ow_device_name() { case "$1" in ''|lo|br-lan|*[!a-zA-Z0-9_.:@-]*) return 1;; *) return 0;; esac; }
ow_validate_config() {
    case "$MODE" in dynamic|fixed) ;; *) return 1;; esac
    case "$SOURCE" in wan|external) ;; *) return 1;; esac
    case "$CHALLENGE" in http|alpn) ;; *) return 1;; esac
    case "$DEPLOY" in files|uhttpd) ;; *) return 1;; esac
    ow_name "$NETWORK" && [ "$NETWORK" != lan ] || return 1
    ow_name "$UHTTPD_SECTION" || return 1
    case "$EMAIL" in *@*.*) ;; *) return 1;; esac
    case "$EMAIL" in *[!a-zA-Z0-9._+@-]*) return 1;; esac
    if [ "$MODE" = fixed ]; then FIXED_IP=$(ow_ip "$FIXED_IP" "$FAMILY") || return 1; fi
}
ow_load() {
    ow_paths "$1"
    [ -r "$CONF" ] || ow_die "IPv$FAMILY 尚未配置。"
    MODE=''; SOURCE=''; NETWORK=''; FIXED_IP=''; EMAIL=''; CHALLENGE=''; DEPLOY=''; UHTTPD_SECTION=main; RELOAD_CMD=''
    # Never source a config as shell code. Only these literal fields are accepted.
    while IFS='=' read -r k v || [ -n "$k" ]; do
        case "$k" in
            MODE) MODE=$v;; SOURCE) SOURCE=$v;; NETWORK) NETWORK=$v;; FIXED_IP) FIXED_IP=$v;;
            EMAIL) EMAIL=$v;; CHALLENGE) CHALLENGE=$v;; DEPLOY) DEPLOY=$v;;
            UHTTPD_SECTION) UHTTPD_SECTION=$v;; RELOAD_CMD) RELOAD_CMD=$v;;
            '') ;; *) ow_die "未知配置项：$k";;
        esac
    done < "$CONF"
    ow_validate_config || ow_die '配置校验失败，请重新配置。'
}
ow_save_config() {
    ow_validate_config || ow_die '配置校验失败。'
    {
        printf 'MODE=%s\nSOURCE=%s\nNETWORK=%s\nFIXED_IP=%s\nEMAIL=%s\n' "$MODE" "$SOURCE" "$NETWORK" "$FIXED_IP" "$EMAIL"
        printf 'CHALLENGE=%s\nDEPLOY=%s\nUHTTPD_SECTION=%s\nRELOAD_CMD=%s\n' "$CHALLENGE" "$DEPLOY" "$UHTTPD_SECTION" "$RELOAD_CMD"
    } > "$CONF.new"
    chmod 600 "$CONF.new"
    mv -f "$CONF.new" "$CONF"
}
ow_dependencies() {
    if command -v apk >/dev/null 2>&1; then
        apk update || ow_die 'apk 软件源更新失败。'
        apk add curl ca-bundle openssl-util socat flock jsonfilter || ow_die 'apk 依赖安装失败。'
    elif command -v opkg >/dev/null 2>&1; then
        opkg update || ow_die 'opkg 软件源更新失败。'
        opkg install curl ca-bundle openssl-util socat flock jsonfilter || ow_die 'opkg 依赖安装失败。'
    else ow_die '没有找到 OpenWrt 的 opkg / apk 包管理器。'; fi
    for cmd in curl openssl socat flock jsonfilter ubus uci setsid; do
        command -v "$cmd" >/dev/null 2>&1 || ow_die "缺少 $cmd，请检查固件软件源。"
    done
    [ -x "$OW_INIT/cron" ] || ow_die '当前固件缺少 cron 服务。'
}
ow_client() {
    if [ ! -s "$OW_ACME" ]; then
        mkdir -p "$(dirname "$OW_ACME")"
        curl -q -fsS --proto '=https' --connect-timeout 10 --max-time 120 \
            https://raw.githubusercontent.com/acmesh-official/acme.sh/master/acme.sh -o "$OW_ACME.new"
        sh -n "$OW_ACME.new"
        grep -q -- '--cert-profile' "$OW_ACME.new" || ow_die '下载的 acme.sh 不支持证书 Profile。'
        chmod 700 "$OW_ACME.new"
        mv -f "$OW_ACME.new" "$OW_ACME"
    fi
    grep -q -- '--cert-profile' "$OW_ACME" || ow_die '现有专用 acme.sh 太旧，请更新客户端。'
}
ow_network() {
    NETJSON=$(ubus call "network.interface.$NETWORK" status) || return 1
    WAN_DEVICE=$(printf '%s' "$NETJSON" | jsonfilter -e '@.l3_device') || return 1
    ow_device_name "$WAN_DEVICE" || return 1
    [ "$(printf '%s' "$NETJSON" | jsonfilter -e '@.up')" = true ] || return 1
    if [ "$FAMILY" = 4 ]; then
        LOCAL_ADDRESS=$(printf '%s' "$NETJSON" | jsonfilter -e '@["ipv4-address"][0].address')
        LOCAL_ADDRESS=$(ow_ip "$LOCAL_ADDRESS" 4 0) || return 1
    else
        LOCAL_ADDRESS=''
        previous=$(cat "$STATE" 2>/dev/null || true)
        if [ "$MODE" = fixed ]; then previous=$FIXED_IP; fi
        for address in $(printf '%s' "$NETJSON" | jsonfilter -e '@["ipv6-address"][*].address'); do
            canonical=$(ow_ip "$address" 6) || continue
            [ -n "$LOCAL_ADDRESS" ] || LOCAL_ADDRESS=$canonical
            if [ "$canonical" = "$previous" ]; then LOCAL_ADDRESS=$canonical; break; fi
        done
        [ -n "$LOCAL_ADDRESS" ] || return 1
    fi
}
ow_detect() {
    if [ "$MODE" = fixed ]; then printf '%s\n' "$FIXED_IP"; return; fi
    if [ "$SOURCE" = wan ]; then ow_ip "$LOCAL_ADDRESS" "$FAMILY"; return; fi
    if [ "$FAMILY" = 4 ]; then hosts='4.ipw.cn api4.ipify.org ipv4.icanhazip.com'
    else hosts='6.ipw.cn api6.ipify.org ipv6.icanhazip.com'; fi
    for host in $hosts; do
        raw=$(curl -q --noproxy '*' --proxy '' --interface "$WAN_DEVICE" --proto '=https' \
            "-$FAMILY" -fsS --connect-timeout 3 --max-time 6 --max-filesize 1024 "https://$host" 2>/dev/null) || continue
        if normalized=$(ow_ip "$raw" "$FAMILY"); then printf '%s\n' "$normalized"; return 0; fi
    done
    return 1
}
ow_acme() (
    # Isolate the entire ACME/socat process group, not just the ACME shell.
    # Child daemons must never inherit the manager's flock descriptor.
    exec 9>&-
    mkdir -p "$ACME_CONFIG/certs" || exit 1
    command -v setsid >/dev/null 2>&1 || { ow_log '缺少 setsid，无法安全管理验证进程。'; exit 1; }
    limit=${SSL_RENEWAL_OPENWRT_ACME_TIMEOUT:-600}
    case "$limit" in ''|*[!0-9]*) exit 1;; esac
    [ "$limit" -ge 1 ] && [ "$limit" -le 600 ] || exit 1
    acme_pid=''; guard_pid=''
    acme_cleanup() {
        if [ -n "$acme_pid" ] && kill -TERM "-$acme_pid" 2>/dev/null; then
            sleep 1
            kill -KILL "-$acme_pid" 2>/dev/null || true
        fi
        if [ -n "$guard_pid" ]; then
            kill "$guard_pid" 2>/dev/null || true
            wait "$guard_pid" 2>/dev/null || true
        fi
    }
    trap acme_cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    # A noninteractive background child is not the shell's process-group leader,
    # so setsid execs in place and acme_pid is also the new process-group ID.
    setsid sh "$OW_ACME" --home "$(dirname "$OW_ACME")" \
        --config-home "$ACME_CONFIG" --cert-home "$ACME_CONFIG/certs" \
        --server letsencrypt "$@" </dev/null &
    acme_pid=$!
    (
        sleeper=''
        trap '[ -z "$sleeper" ] || kill "$sleeper" 2>/dev/null || true' EXIT
        trap 'exit 0' INT TERM
        sleep "$limit" & sleeper=$!
        wait "$sleeper" || exit 0
        kill -TERM "-$acme_pid" 2>/dev/null || exit 0
        sleep 5 & sleeper=$!
        wait "$sleeper" || exit 0
        kill -KILL "-$acme_pid" 2>/dev/null || true
    ) </dev/null >/dev/null 2>&1 &
    guard_pid=$!
    rc=0
    wait "$acme_pid" || rc=$?
    exit "$rc"
)
ow_port_free() {
    if command -v ss >/dev/null 2>&1; then sockets=$(ss -ltn 2>/dev/null) || return 1
    elif command -v netstat >/dev/null 2>&1; then sockets=$(netstat -ltn 2>/dev/null) || return 1
    else return 1; fi
    printf '%s\n' "$sockets" | awk -v port=":$1" '$4 ~ port "$" {found=1} END {exit found?1:0}'
}
ow_firewall_kind() {
    if command -v nft >/dev/null 2>&1 && nft list chain inet fw4 dstnat >/dev/null 2>&1 && nft list chain inet fw4 input >/dev/null 2>&1; then
        OW_FW_KIND=nft
    elif [ "$FAMILY" = 4 ] && command -v iptables >/dev/null 2>&1; then OW_FW_KIND=iptables
    elif [ "$FAMILY" = 6 ] && command -v ip6tables >/dev/null 2>&1; then OW_FW_KIND=ip6tables
    else return 1; fi
}
ow_firewall_remove() {
    [ -n "${OW_FW_TAG:-}" ] || return 0
    if [ "$OW_FW_KIND" = nft ]; then
        for chain in dstnat input; do
            handles=$(nft -a list chain inet fw4 "$chain" 2>/dev/null | awk -v tag="$OW_FW_TAG" 'index($0,"\"" tag "\"") {for(i=1;i<=NF;i++)if($i=="handle" && $(i+1)~/^[0-9]+$/)print $(i+1)}')
            for h in $handles; do nft delete rule inet fw4 "$chain" handle "$h" 2>/dev/null || true; done
        done
    else
        "$OW_FW_KIND" -t nat -D PREROUTING -i "$WAN_DEVICE" -d "$LOCAL_ADDRESS" -p tcp --dport "$PUBLIC_PORT" \
            -m comment --comment "$OW_FW_TAG" -j DNAT --to-destination "$NAT_DEST" 2>/dev/null || true
        "$OW_FW_KIND" -D INPUT -i "$WAN_DEVICE" -p tcp --dport "$LOCAL_PORT" -m conntrack --ctstatus DNAT \
            -m comment --comment "$OW_FW_TAG" -j ACCEPT 2>/dev/null || true
    fi
}
ow_firewall_start() {
    ow_firewall_kind || ow_die '不支持此防火墙，未修改任何现有规则。'
    if [ "$CHALLENGE" = http ]; then PUBLIC_PORT=80; LOCAL_PORT=$((38080 + FAMILY))
    else PUBLIC_PORT=443; LOCAL_PORT=$((38443 + FAMILY)); fi
    if [ "$FAMILY" = 6 ]; then NAT_DEST="[$LOCAL_ADDRESS]:$LOCAL_PORT"; else NAT_DEST="$LOCAL_ADDRESS:$LOCAL_PORT"; fi
    ow_port_free "$LOCAL_PORT" || ow_die "专用本地端口 $LOCAL_PORT 已占用或无法检查。"
    # Only selected WAN + local destination + current address family is redirected.
    # No LAN interception, no LuCI exposure, no permanent firewall configuration.
    OW_FW_TAG="sslr-ow-$$-$(date +%s)"
    # Start the bounded cleanup lease BEFORE adding even the first rule.
    ( trap 'kill "$sleeper" 2>/dev/null || true' EXIT
      sleep 900 & sleeper=$!
      trap 'exit 0' INT TERM
      wait "$sleeper"
      ow_firewall_remove
    ) 9>&- </dev/null >/dev/null 2>&1 &
    OW_WATCH_PID=$!
    if [ "$OW_FW_KIND" = nft ]; then
        if [ "$FAMILY" = 4 ]; then nfproto=ipv4; addrtype=ip; else nfproto=ipv6; addrtype=ip6; fi
        nft insert rule inet fw4 dstnat iifname "$WAN_DEVICE" meta nfproto "$nfproto" "$addrtype" daddr "$LOCAL_ADDRESS" \
            tcp dport "$PUBLIC_PORT" dnat "$addrtype" to "$NAT_DEST" comment "\"$OW_FW_TAG\""
        nft insert rule inet fw4 input iifname "$WAN_DEVICE" meta nfproto "$nfproto" tcp dport "$LOCAL_PORT" \
            ct status dnat accept comment "\"$OW_FW_TAG\""
    else
        "$OW_FW_KIND" -t nat -I PREROUTING 1 -i "$WAN_DEVICE" -d "$LOCAL_ADDRESS" -p tcp --dport "$PUBLIC_PORT" \
            -m comment --comment "$OW_FW_TAG" -j DNAT --to-destination "$NAT_DEST"
        "$OW_FW_KIND" -I INPUT 1 -i "$WAN_DEVICE" -p tcp --dport "$LOCAL_PORT" -m conntrack --ctstatus DNAT \
            -m comment --comment "$OW_FW_TAG" -j ACCEPT
    fi
}
ow_cleanup() {
    ow_firewall_remove
    if [ -n "$OW_WATCH_PID" ]; then kill "$OW_WATCH_PID" 2>/dev/null || true; wait "$OW_WATCH_PID" 2>/dev/null || true; fi
    OW_WATCH_PID=''; OW_FW_TAG=''
    [ -z "$OW_STAGE" ] || rm -rf "$OW_STAGE"
}

# Verify trust, time, IP SAN and key pairing, not just that files are nonempty.
ow_certificate_valid() (
    cert=$1; key=$2; target=$3; seconds=${4:-3600}
    [ -s "$cert" ] && [ -s "$key" ] || exit 1
    t=$(mktemp -d "$OW_RUN/verify.XXXXXX") || exit 1
    trap 'rm -rf "$t"' EXIT
    openssl x509 -in "$cert" -out "$t/leaf.pem" >/dev/null 2>&1 || exit 1
    openssl x509 -in "$cert" -checkend "$seconds" -noout >/dev/null 2>&1 || exit 1
    openssl verify -purpose sslserver -verify_ip "$target" -untrusted "$cert" "$t/leaf.pem" >/dev/null 2>&1 || exit 1
    openssl x509 -in "$cert" -pubkey -noout > "$t/cert.pub" 2>/dev/null || exit 1
    openssl pkey -in "$key" -pubout > "$t/key.pub" 2>/dev/null || exit 1
    cmp -s "$t/cert.pub" "$t/key.pub"
)
ow_retry_ready() {
    [ -f "$RETRY" ] || return 0
    IFS='|' read -r retry_ip failures next_try < "$RETRY" || return 0
    case "$next_try" in ''|*[!0-9]*) return 0;; esac
    [ "$retry_ip" != "$TARGET" ] || [ "$(date +%s)" -ge "$next_try" ]
}
ow_failed() {
    failures=0
    if [ -f "$RETRY" ]; then
        IFS='|' read -r prior_ip failures ignored < "$RETRY" || failures=0
        [ "$prior_ip" = "$TARGET" ] || failures=0
    fi
    case "$failures" in ''|*[!0-9]*) failures=0;; esac
    [ "$failures" -lt 6 ] || failures=5
    failures=$((failures + 1)); delay=900; i=1
    while [ "$i" -lt "$failures" ]; do delay=$((delay * 2)); i=$((i + 1)); done
    [ "$delay" -le 21600 ] || delay=21600
    printf '%s|%s|%s\n' "$TARGET" "$failures" "$(( $(date +%s) + delay ))" > "$RETRY"
    ow_log "本次未完成，旧的已部署证书保留；$delay 秒后允许自动重试。"
}
ow_link() {
    ln -s "$1" "$CERTROOT/current.new" || return 1
    mv -Tf "$CERTROOT/current.new" "$CERTROOT/current"
}
ow_restore_uci() {
    if [ -n "$old_cert_option" ]; then uci set "uhttpd.$UHTTPD_SECTION.cert=$old_cert_option"
    else uci -q delete "uhttpd.$UHTTPD_SECTION.cert" || true; fi
    if [ -n "$old_key_option" ]; then uci set "uhttpd.$UHTTPD_SECTION.key=$old_key_option"
    else uci -q delete "uhttpd.$UHTTPD_SECTION.key" || true; fi
    uci commit uhttpd
}
ow_deploy() (
    # Both files are immutable within a generation; one symlink switches the pair.
    set -e
    mkdir -p "$CERTROOT"
    [ ! -e "$CERTROOT/current" ] || [ -L "$CERTROOT/current" ] || exit 1
    old=$(readlink "$CERTROOT/current" 2>/dev/null || true)
    case "$old" in ''|g-*) ;; *) exit 1;; esac
    generation=$(mktemp -d "$CERTROOT/g-XXXXXX")
    generation_name=${generation##*/}
    switched=0; finished=0; uci_changed=0
    old_cert_option=''; old_key_option=''
    rollback() {
        if [ "$finished" != 1 ]; then
            if [ "$switched" = 1 ]; then
                rm -f "$CERTROOT/current.new"
                if [ -n "$old" ]; then ow_link "$old" || true; else rm -f "$CERTROOT/current"; fi
            fi
            if [ "$uci_changed" = 1 ]; then ow_restore_uci || true; fi
            if [ "$switched" = 1 ]; then
                if [ "$DEPLOY" = uhttpd ]; then "$OW_INIT/uhttpd" restart >/dev/null 2>&1 || true
                elif [ -n "$RELOAD_CMD" ]; then sh -c "$RELOAD_CMD" >/dev/null 2>&1 || true; fi
            fi
            rm -rf "$generation"
        fi
        rm -f "$CERTROOT/current.new"
    }
    trap rollback EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    cp "$PENDING/fullchain.pem" "$generation/fullchain.pem"
    cp "$PENDING/privkey.pem" "$generation/privkey.pem"
    chmod 600 "$generation/privkey.pem"
    chmod 644 "$generation/fullchain.pem"
    if [ "$DEPLOY" = uhttpd ]; then
        [ "$(uci -q get "uhttpd.$UHTTPD_SECTION")" = uhttpd ] || exit 1
        old_cert_option=$(uci -q get "uhttpd.$UHTTPD_SECTION.cert" || true)
        old_key_option=$(uci -q get "uhttpd.$UHTTPD_SECTION.key" || true)
        mkdir -p "$OW_BASE/backups"
        if [ ! -f "$OW_BASE/backups/uhttpd.original" ]; then uci export uhttpd > "$OW_BASE/backups/uhttpd.original"; fi
    fi
    rm -f "$CERTROOT/current.new"
    ow_link "$generation_name"
    switched=1
    if [ "$DEPLOY" = uhttpd ]; then
        uci_changed=1
        uci set "uhttpd.$UHTTPD_SECTION.cert=$CERTROOT/current/fullchain.pem"
        uci set "uhttpd.$UHTTPD_SECTION.key=$CERTROOT/current/privkey.pem"
        uci commit uhttpd
        "$OW_INIT/uhttpd" restart
    elif [ -n "$RELOAD_CMD" ]; then sh -c "$RELOAD_CMD"; fi
    finished=1
    # Only prune this manager's old generations, retaining current + previous.
    for d in "$CERTROOT"/g-*; do
        [ -d "$d" ] || continue
        [ "$d" = "$generation" ] || [ "${d##*/}" = "$old" ] || rm -rf "$d"
    done
)
ow_run_check() {
    ow_require
    [ ! -f "$OW_RUN/uninstalled" ] || { ow_log '本项目已卸载，请重新安装并恢复自动管理。'; return 0; }
    ow_dirs
    ow_lock
    # Re-read after taking the uninstall/operation lock, never use stale config.
    [ ! -f "$OW_RUN/uninstalled" ] || return 0
    ow_load "$1"
    [ ! -f "$DISABLED" ] || { ow_log "IPv$FAMILY 已停用自动管理（证书保留）。"; return 0; }
    [ -s "$OW_ACME" ] || ow_die '请先完成开通，专用 ACME 客户端不存在。'
    ow_network || ow_die "接口 $NETWORK 未就绪/地址不可用，请检查 WAN。"
    TARGET=$(ow_detect) || ow_die '未获得可用公网 IP；WAN 为私网时可选择出口检测，但仍需公网端口映射。'
    # IPv6 cannot use a different machine or a delegated prefix as the certificate endpoint.
    if [ "$FAMILY" = 6 ] && [ "$TARGET" != "$LOCAL_ADDRESS" ]; then
        ow_die '目标 IPv6 与选定接口地址不同，请使用实际承载服务的稳定接口地址。'
    fi
    config_digest=$(sha256sum "$CONF" | awk '{print $1}')
    if ow_certificate_valid "$CERTROOT/current/fullchain.pem" "$CERTROOT/current/privkey.pem" "$TARGET" 259200; then
        if [ "$(cat "$RECEIPT" 2>/dev/null || true)" = "$TARGET|$config_digest" ]; then
            ow_log "IPv$FAMILY：$TARGET 未变化且证书有效期充足，无需签发。"
            return 0
        fi
        # Changing deployment settings must apply even when the IP did not change.
        mkdir -p "$PENDING"
        cp "$CERTROOT/current/fullchain.pem" "$PENDING/fullchain.pem"
        cp "$CERTROOT/current/privkey.pem" "$PENDING/privkey.pem"
    fi
    if ! ow_retry_ready; then ow_log '上次失败后的退避期内，本次不向 CA 重试。'; return 0; fi
    success=0
    trap 'ow_cleanup; if [ "$success" != 1 ]; then ow_failed; fi' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    mkdir -p "$PENDING" "$ACME_CONFIG"
    # A previous issuance may have succeeded while service reload failed. Reuse it.
    if ! ow_certificate_valid "$PENDING/fullchain.pem" "$PENDING/privkey.pem" "$TARGET" 259200; then
        if [ ! -f "$ACME_CONFIG/account.ready" ]; then
            ow_acme --register-account -m "$EMAIL"
            : > "$ACME_CONFIG/account.ready"
        fi
        ow_firewall_start
        ow_log "为 $TARGET 申请/续签，公网 TCP $PUBLIC_PORT 临时用于验证；不修改 LAN 管理入口。"
        if [ "$CHALLENGE" = http ]; then
            set -- --standalone --httpport "$LOCAL_PORT"
        else set -- --alpn --tlsport "$LOCAL_PORT"; fi
        if [ "$FAMILY" = 4 ]; then set -- "$@" --listen-v4; else set -- "$@" --listen-v6; fi
        rc=0
        ow_acme --issue -d "$TARGET" --cert-profile shortlived --days 3 --keylength ec-256 \
            --local-address "$LOCAL_ADDRESS" "$@" || rc=$?
        ow_cleanup
        case "$rc" in 0|2) ;; *) ow_die "签发失败（$rc），请检查公网端口/NAT/运营商限制。";; esac
        ow_acme --install-cert -d "$TARGET" --ecc --key-file "$PENDING/privkey.pem" --fullchain-file "$PENDING/fullchain.pem"
        if [ "$rc" = 2 ] && ! ow_certificate_valid "$PENDING/fullchain.pem" "$PENDING/privkey.pem" "$TARGET" 259200; then
            ow_die '客户端跳过签发，但缓存证书有效期不足；保留旧部署并退避重试，不自动强制签发。'
        fi
    else ow_log '复用已签发的待部署证书，不重新向 CA 申请。'; fi
    ow_certificate_valid "$PENDING/fullchain.pem" "$PENDING/privkey.pem" "$TARGET" 3600 || ow_die '证书的信任链、IP、有效期或私钥不匹配，拒绝部署。'
    FIRST_TARGET=$TARGET
    ow_network || ow_die '签发期间 WAN 离线，暂不部署。'
    TARGET=$(ow_detect) || ow_die '签发后无法再次确认公网 IP，暂不部署。'
    [ "$FIRST_TARGET" = "$TARGET" ] || ow_die '签发期间 IP 再次变化，暂不部署刚才的证书。'
    ow_deploy
    old_ip=$(cat "$STATE" 2>/dev/null || true)
    printf '%s\n' "$TARGET" > "$STATE.new"
    mv -f "$STATE.new" "$STATE"
    printf '%s|%s\n' "$TARGET" "$config_digest" > "$RECEIPT.new"
    mv -f "$RECEIPT.new" "$RECEIPT"
    rm -f "$RETRY"
    success=1
    if [ -n "$old_ip" ] && [ "$old_ip" != "$TARGET" ]; then
        ow_acme --remove -d "$old_ip" --ecc >/dev/null 2>&1 || true
    fi
    ow_log "已更新 IPv$FAMILY：$TARGET；证书：$CERTROOT/current/fullchain.pem"
    ow_log "私钥：$CERTROOT/current/privkey.pem（仅保存在软路由）。"
}

ow_cron() {
    # Preserve every unrelated job. Read the actual OpenWrt root crontab, not an
    # ambiguous crontab -l failure which could erase an existing crontab.
    mkdir -p "$(dirname "$OW_CRONTAB")"
    [ -f "$OW_CRONTAB" ] || : > "$OW_CRONTAB"
    awk -v marker="$OW_MARKER" 'index($0,marker)==0' "$OW_CRONTAB" > "$OW_CRONTAB.sslrenewal"
    active=0
    for f in 4 6; do
        if [ -f "$OW_BASE/v$f.conf" ] && [ ! -f "$OW_BASE/v$f.disabled" ]; then active=1; fi
    done
    if [ "$active" = 1 ]; then
        printf '*/5 * * * * /bin/sh %s check-all >/dev/null 2>&1 %s\n' "$OW_SELF" "$OW_MARKER" >> "$OW_CRONTAB.sslrenewal"
    fi
    chmod 600 "$OW_CRONTAB.sslrenewal"
    mv -f "$OW_CRONTAB.sslrenewal" "$OW_CRONTAB"
    "$OW_INIT/cron" enable
    "$OW_INIT/cron" start
}
ow_status() {
    for f in 4 6; do
        if [ ! -f "$OW_BASE/v$f.conf" ]; then printf 'IPv%s：未配置\n' "$f"; continue; fi
        (
            ow_load "$f"
            printf '\nIPv%s：模式=%s；接口=%s；验证=%s；部署=%s\n' "$f" "$MODE" "$NETWORK" "$CHALLENGE" "$DEPLOY"
            [ ! -f "$DISABLED" ] && echo '自动管理：已配置启用（请同时检查 cron 服务）' || echo '自动管理：已停用，证书不会自动续签'
            printf '上次成功 IP：'; cat "$STATE" 2>/dev/null || echo '尚未成功'
            printf '证书：%s/current/fullchain.pem\n私钥：%s/current/privkey.pem\n' "$CERTROOT" "$CERTROOT"
            if [ -s "$CERTROOT/current/fullchain.pem" ]; then openssl x509 -in "$CERTROOT/current/fullchain.pem" -noout -dates; fi
            if [ -f "$RETRY" ]; then printf '失败退避（IP|次数|下次时间戳）：'; cat "$RETRY"; fi
        )
    done
    echo '日志：logread -e ssl-renewal-openwrt'
}
ow_prompt() { printf '%s' "$1"; IFS= read -r ANSWER; }
ow_setup() {
    ow_require
    ow_dirs
    ow_prompt '地址类型：1）IPv4  2）IPv6  0）返回 [1]：' || return 0
    case "${ANSWER:-1}" in 1) ow_paths 4;; 2) ow_paths 6;; 0) return 0;; *) ow_die '无效选项。';; esac
    if [ -f "$CONF" ]; then
        ow_prompt '已有配置，重新设置请输入 RECONFIGURE（回车取消）：' || return 0
        [ "$ANSWER" = RECONFIGURE ] || return 0
    fi
    ow_prompt 'IP 类型：1）动态公网 IP（推荐） 2）固定公网 IP [1]：' || return 0
    case "${ANSWER:-1}" in 1) MODE=dynamic;; 2) MODE=fixed;; *) ow_die '无效选项。';; esac
    EMAIL=''; FIXED_IP=''; SOURCE=wan; CHALLENGE=http; DEPLOY=files; UHTTPD_SECTION=main; RELOAD_CMD=''
    [ "$FAMILY" = 4 ] && default_network=wan || default_network=wan6
    ow_prompt "面向公网的 OpenWrt 逻辑接口 [$default_network]：" || return 0
    NETWORK=${ANSWER:-$default_network}
    ow_name "$NETWORK" && [ "$NETWORK" != lan ] || ow_die '请填写面向公网的逻辑接口，不是 lan。'
    if [ "$MODE" = dynamic ]; then
        ow_prompt '地址来源：1）WAN 接口地址（推荐） 2）出口检测（光猫路由/NAT） [1]：' || return 0
        case "${ANSWER:-1}" in 1) SOURCE=wan;; 2) SOURCE=external;; *) ow_die '无效选项。';; esac
    else
        ow_prompt '输入固定公网 IP（仅地址）：' || return 0
        FIXED_IP=$(ow_ip "$ANSWER" "$FAMILY") || ow_die '不是支持的公网单播 IP。'
    fi
    ow_prompt '电子邮件地址：' || return 0
    EMAIL=$ANSWER
    ow_prompt '公网验证：1）HTTP-01 TCP80（推荐） 2）TLS-ALPN-01 TCP443 [1]：' || return 0
    case "${ANSWER:-1}" in 1) CHALLENGE=http;; 2) CHALLENGE=alpn;; *) ow_die '无效选项。';; esac
    ow_prompt '证书用途：1）仅保存证书（默认） 2）应用到 uHTTPd/LuCI [1]：' || return 0
    case "${ANSWER:-1}" in
        1)
            DEPLOY=files
            ow_prompt '更新后重载命令（可留空；例如 /etc/init.d/nginx reload）：' || return 0
            RELOAD_CMD=$ANSWER
            ;;
        2)
            DEPLOY=uhttpd
            ow_prompt 'uHTTPd 配置实例名称 [main]：' || return 0
            UHTTPD_SECTION=${ANSWER:-main}
            [ "$(uci -q get "uhttpd.$UHTTPD_SECTION")" = uhttpd ] || ow_die '找不到该 uHTTPd 实例。'
            other=4; [ "$FAMILY" = 4 ] && other=6
            if [ -f "$OW_BASE/v$other.conf" ] && grep -q '^DEPLOY=uhttpd$' "$OW_BASE/v$other.conf" &&
                grep -qx "UHTTPD_SECTION=$UHTTPD_SECTION" "$OW_BASE/v$other.conf"; then
                ow_die '另一地址族已配置此 uHTTPd 实例，请勿用两张单 IP 证书互相覆盖；可选择仅保存证书。'
            fi
            ;;
        *) ow_die '无效选项。';;
    esac
    ow_validate_config || ow_die '配置不合法。'
    echo '此模式在软路由本机运行，不需要云服务器、SSH 隧道或 ZeroTier。'
    echo '将安装 curl/openssl/socat/flock 等依赖，按需临时接管选定 WAN 的验证端口。'
    echo '不开放 LuCI、不关闭防火墙；公网验证端口仍需运营商允许、上级 NAT 正确映射。'
    echo '验证期间该 WAN 端口的普通访问会短暂中断；IP 证书只匹配该公网 IP。'
    [ "$DEPLOY" != uhttpd ] || echo '将备份 uHTTPd 配置、修改此实例证书路径并重启 uHTTPd；内网 IP 访问不匹配此证书。'
    ow_prompt '确认申请并安装依赖？输入 yes / YES（回车取消）：' || return 0
    case "$ANSWER" in
        [Yy][Ee][Ss]) ;;
        *) echo '已取消，未安装依赖。'; return 0;;
    esac
    ow_dependencies
    ow_lock
    ow_client
    ow_network || ow_die '所选 WAN 接口未就绪。'
    TARGET=$(ow_detect) || ow_die '检测不到公网 IP：光猫路由时改选出口检测；CGNAT 不能直接验证。'
    ow_log "本次目标：$TARGET；接口：$NETWORK ($WAN_DEVICE)"
    ow_firewall_kind || ow_die '不支持当前防火墙，未安装自动任务。'
    ow_save_config
    rm -f "$DISABLED" "$RETRY"
    rm -f "$OW_RUN/uninstalled"
    ow_cron
    exec 9>&-
    ow_log '已启用每 5 分钟检查：IP 变化时重签，IP 未变但证书剩余不足 3 天时续签。'
    # New process preserves fail-fast semantics and acquires its own operation lock.
    sh "$OW_SELF" check "$FAMILY"
}
ow_toggle() {
    ow_require
    ow_dirs
    ow_prompt '地址类型：1）IPv4 2）IPv6 0）返回 [1]：' || return 0
    case "${ANSWER:-1}" in 1) ow_paths 4;; 2) ow_paths 6;; 0) return 0;; *) ow_die '无效选项。';; esac
    [ -f "$CONF" ] || ow_die '尚未配置。'
    ow_lock
    if [ -f "$DISABLED" ]; then
        # A keep-data uninstall removes the dedicated client, not its accounts.
        # Restore it before re-enabling jobs after the user explicitly reinstalls.
        ow_client
        rm -f "$DISABLED" "$RETRY"
        rm -f "$OW_RUN/uninstalled"
        ow_cron
        ow_log "IPv$FAMILY 自动管理已恢复。"
    else
        echo '停用后 IP 变化重签和到期续签都会停止，已有证书/私钥保留，但会自然过期。'
        ow_prompt '确认停用？输入 STOP：' || return 0
        [ "$ANSWER" = STOP ] || return 0
        : > "$DISABLED"
        ow_cron
        ow_log "IPv$FAMILY 自动管理已停用。"
    fi
}
# Uninstall never removes shared opkg/apk packages or restores the entire router
# configuration. Clean mode archives data and relocates only active uHTTPd paths.
ow_safe_uninstall_path() {
    case "$1" in /|/etc|/root|/tmp|/usr|/var|/home|''|*/../*|*/..|*/./*|*/.|*'|'*) return 1;; /*) ;; *) return 1;; esac
    check_path=$1
    while [ "$check_path" != / ]; do
        [ ! -L "$check_path" ] || return 1
        check_path=${check_path%/*}
        [ -n "$check_path" ] || check_path=/
    done
}
ow_uninstall_luci() (
    set -e
    backup=$1
    snapshot="$backup/uhttpd-paths.before"
    : > "$snapshot"
    if ! command -v uci >/dev/null 2>&1; then
        [ ! -f /etc/config/uhttpd ] || ow_die '缺少 uci，无法安全处理 LuCI 证书路径。'
        exit 0
    fi
    if ! listing=$(uci -q show uhttpd); then
        [ ! -f /etc/config/uhttpd ] || ow_die '无法读取 uHTTPd，清理已中止。'
        exit 0
    fi
    keys=$(printf '%s\n' "$listing" | awk -F= '$1 ~ /^uhttpd\.[a-zA-Z0-9_@.\[\]-]+\.(cert|key)$/ {print $1}')
    for option in $keys; do
        oldpath=$(uci -q get "$option") || exit 1
        resolved=$(readlink -f "$oldpath" 2>/dev/null || true)
        case "$resolved" in "$OW_BASE"/*) ;; *)
            case "$oldpath" in "$OW_BASE"/*) ow_die "证书引用已损坏：$option；请先修复或选择保留卸载。";; esac
            continue;;
        esac
        case "$oldpath$resolved" in *'|'*) ow_die '证书路径含不支持的分隔符。';; esac
        newpath="$backup/data/${resolved#"$OW_BASE"/}"
        [ -s "$newpath" ] && cmp -s "$oldpath" "$newpath" || ow_die '证书备份验证失败，保留原部署。'
        printf '%s|%s|%s\n' "$option" "$oldpath" "$newpath" >> "$snapshot"
    done
    [ -s "$snapshot" ] || exit 0
    changes=$(uci changes uhttpd) || exit 1
    [ -z "$changes" ] || ow_die 'uHTTPd 有尚未提交的修改，请保存/撤销后再卸载。'
    [ -x "$OW_INIT/uhttpd" ] || ow_die '找不到 uHTTPd 服务，未删除证书。'
    done_ok=0
    rollback_uninstall_uci() {
        if [ "$done_ok" != 1 ]; then
            while IFS='|' read -r option oldpath newpath; do uci set "$option=$oldpath" || true; done < "$snapshot"
            uci commit uhttpd || true
            "$OW_INIT/uhttpd" restart >/dev/null 2>&1 || true
        fi
    }
    trap rollback_uninstall_uci EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    while IFS='|' read -r option oldpath newpath; do uci set "$option=$newpath"; done < "$snapshot"
    uci commit uhttpd
    "$OW_INIT/uhttpd" restart
    done_ok=1
    ow_log 'LuCI 已改为读取备份中的同一张证书；保留其他 uHTTPd 设置，不降级到 HTTP。'
)
ow_uninstall() {
    ow_require
    echo '\n============ OpenWrt 卸载 ============'
    echo '1）卸载程序（保留证书和配置）【默认】'
    echo '2）备份后清理本项目证书/配置并卸载（方便重新配置）'
    echo '0）取消'
    ow_prompt '请选择 [1]：' || return 0
    removal=${ANSWER:-1}
    case "$removal" in 0) return 0;; 1|2) ;; *) ow_log '无效选项，未卸载。'; return 0;; esac
    echo "将移除本项目自动任务和程序：$OW_SELF"
    echo "数据目录：$OW_BASE；备份目录：$OW_BACKUPS"
    echo '两种方式均停止 IP 重签和到期续签；证书会自然过期，不会撤销证书。'
    echo '不卸载系统依赖，不关闭 cron/防火墙，不修改 SSH 或其他网络设置。'
    token=UNINSTALL
    if [ "$removal" = 2 ]; then
        token=PURGE
        echo '清理前备份。LuCI 引用会迁移到备份证书并重启 uHTTPd；不是恢复整个旧配置。'
        echo 'Nginx 等其他服务的证书引用需先自行迁移；确认后才清理本项目数据。'
    fi
    ow_prompt "输入 $token 确认（回车取消）：" || return 0
    [ "$ANSWER" = "$token" ] || { ow_log '已取消，未卸载。'; return 0; }
    for path in "$OW_BASE" "$OW_RUN" "$OW_SELF" "$OW_CRONTAB" "$OW_BACKUPS"; do
        ow_safe_uninstall_path "$path" || ow_die "拒绝危险路径或符号链接：$path"
    done
    case "$OW_BACKUPS/" in "$OW_BASE/"*|"$OW_RUN/"*) ow_die '备份目录不能放在待清理目录内。';; esac
    case "$OW_SELF" in "$OW_BASE"/*|"$OW_RUN"/*) ow_die '运行脚本不能位于数据或临时目录。';; esac
    if [ -e "$OW_SELF" ]; then
        [ -f "$OW_SELF" ] && grep -q 'ow_main' "$OW_SELF" || ow_die '同名运行文件不属于本项目，拒绝删除。'
    fi
    ow_dirs
    if command -v flock >/dev/null 2>&1; then
        ow_lock
    elif [ -f "$OW_BASE/v4.conf" ] || [ -f "$OW_BASE/v6.conf" ] || [ -d "$OW_BASE/acme" ]; then
        ow_die '已有管理配置但缺少 flock，无法确认任务状态；请修复 flock 后再卸载。'
    fi
    # Unknown files inside the private base might belong to a future version or
    # another application. Do not turn a configuration typo into recursive deletion.
    if [ "$removal" = 2 ]; then
        for item in "$OW_BASE"/* "$OW_BASE"/.[!.]* "$OW_BASE"/..?*; do
            [ -e "$item" ] || [ -L "$item" ] || continue
            case "${item##*/}" in
                v4.conf|v6.conf|v4.ip|v6.ip|v4.deployed|v6.deployed|v4.disabled|v6.disabled|certs|pending|acme|client|backups) ;;
                *) ow_die "数据目录含未知文件，未清理：$item（可选择保留卸载）";;
            esac
        done
    fi
    mkdir -p "$OW_BACKUPS"
    chmod 700 "$OW_BACKUPS"
    backup=$(mktemp -d "$OW_BACKUPS/openwrt-XXXXXX")
    chmod 700 "$backup"
    cp -a "$OW_BASE" "$backup/data"
    [ ! -f "$OW_SELF" ] || cp -p "$OW_SELF" "$backup/openwrt_ip_ssl.sh"
    had_cron=0
    if [ -f "$OW_CRONTAB" ]; then
        had_cron=1
        cp -p "$OW_CRONTAB" "$backup/crontab.before"
        # Exact generated command + marker, never grep out another job's comment.
        expected="*/5 * * * * /bin/sh $OW_SELF check-all >/dev/null 2>&1 $OW_MARKER"
        awk -v expected="$expected" '$0!=expected' "$OW_CRONTAB" > "$backup/crontab.after"
    fi
    if [ "$removal" = 2 ]; then ow_uninstall_luci "$backup"; fi
    if [ "$had_cron" = 1 ]; then
        cmp -s "$OW_CRONTAB" "$backup/crontab.before" || ow_die 'crontab 已变化，未覆盖，请重试。'
        if ! cmp -s "$backup/crontab.before" "$backup/crontab.after"; then
            cp "$backup/crontab.after" "$OW_CRONTAB.sslrenewal-uninstall"
            chmod 600 "$OW_CRONTAB.sslrenewal-uninstall"
            mv -f "$OW_CRONTAB.sslrenewal-uninstall" "$OW_CRONTAB"
        fi
    fi
    : > "$OW_RUN/uninstalled"
    if [ "$removal" = 2 ]; then
        rm -rf "$OW_BASE"
    else
        for f in 4 6; do [ ! -f "$OW_BASE/v$f.conf" ] || : > "$OW_BASE/v$f.disabled"; done
        # Only the dedicated downloaded client is a removable program. Shared
        # /root/.acme.sh and system ACME packages are never uninstall targets.
        if [ ! -L "$OW_BASE/client" ] && [ ! -L "$OW_BASE/client/acme.sh" ]; then
            rm -f "$OW_BASE/client/acme.sh"
        fi
    fi
    rm -f "$OW_SELF"
    # Keep the lock inode and shared packages; no killall, cron disable or nft flush.
    ow_log "卸载完成，备份：$backup"
    ow_log '重新运行原安装命令即可安装；保留配置重装后需从菜单恢复自动管理。'
    ow_log '正在使用的备份证书也会到期，请及时重装或切换到其他续期方案。'
}
ow_main() {
    ow_require
    case "${1:-menu}" in
        setup) ow_setup;;
        check) ow_run_check "${2:-4}";;
        check-all)
            rc=0
            for f in 4 6; do
                [ -f "$OW_BASE/v$f.conf" ] || continue
                if sh "$OW_SELF" check "$f"; then :; else rc=1; fi
            done
            return "$rc"
            ;;
        status) ow_status;;
        toggle) ow_toggle;;
        uninstall) ow_uninstall;;
        menu)
            while :; do
                printf '\n============ OpenWrt 本机 IP 证书 ============\n'
                echo '软路由自己申请和使用证书；无需云服务器或远程 SSH。'
                echo '1）申请 / 重新配置（动态或固定公网 IP）'
                echo '2）查看状态 / 证书路径'
                echo '3）立即检查 IP 和证书有效期'
                echo '4）停用 / 恢复自动管理（保留证书）'
                echo '5）卸载 OpenWrt 本机模式'
                echo '0）退出'
                ow_prompt '请选择：' || return 0
                case "$ANSWER" in
                    1) if sh "$OW_SELF" setup; then :; else echo '本次操作未完成，请查看提示；可返回菜单重试。'; fi;;
                    2) if sh "$OW_SELF" status; then :; else echo '状态读取失败。'; fi;;
                    3) if sh "$OW_SELF" check-all; then :; else echo '检查未完成，请查看日志；不会自动强制重签。'; fi;;
                    4) if sh "$OW_SELF" toggle; then :; else echo '操作未完成。'; fi;;
                    5)
                        if sh "$OW_SELF" uninstall; then
                            [ -f "$OW_SELF" ] || return 0
                        else echo '卸载未完成，证书和配置请勿手动删除，检查上方提示。'; fi
                        ;;
                    0) return 0;;
                    *) echo '无效选项。';;
                esac
            done
            ;;
        *) ow_die '用法：openwrt_ip_ssl.sh [menu|setup|status|check 4/6|check-all|toggle|uninstall]';;
    esac
}

if [ "${SSL_RENEWAL_OPENWRT_LIBRARY:-0}" != 1 ]; then
    set -eu
    ow_main "$@"
fi
