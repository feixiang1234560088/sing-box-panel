#!/bin/bash
#
# sing-box 服务端一键部署脚本（交互式）
# 支持协议: Hysteria2 / VLESS+Reality / AnyTLS / Trojan / Shadowsocks
# 功能: 自动申请证书 / 端口跳跃 / 节点分享链接 / 订阅链接
# 适用: Debian / Ubuntu
#
set -o pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

SB_DIR="/usr/local/sing-box"
SB_BIN="$SB_DIR/sing-box"
SB_ETC="/etc/sing-box"
SB_CONF="$SB_ETC/config.json"
SUB_DIR="$SB_ETC/sub"
PANEL_CFG_F="$SB_ETC/panel.json"
CERT_DIR="$SB_ETC/cert"
ACME="$HOME/.acme.sh/acme.sh"

info()  { echo -e "${BLUE}[*]${NC} $1"; }
ok()    { echo -e "${GREEN}[✓]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
err()   { echo -e "${RED}[✗]${NC} $1"; }
die()   { err "$1"; exit 1; }
title() { echo; echo -e "${BOLD}━━━ $1 ━━━${NC}"; }

[[ $EUID -ne 0 ]] && die "请用 root 运行: sudo bash $0"

# ─────────────────────────────────────────────
# 基础
# ─────────────────────────────────────────────
ensure_deps() {
    local need=()
    for c in curl tar jq openssl socat python3; do
        command -v "$c" >/dev/null 2>&1 || need+=("$c")
    done
    if [[ ${#need[@]} -gt 0 ]]; then
        info "安装依赖: ${need[*]}"
        apt-get update -qq >/dev/null 2>&1
        apt-get install -y -qq "${need[@]}" >/dev/null 2>&1 || die "依赖安装失败"
    fi
}

get_arch() {
    case "$(uname -m)" in
        x86_64|amd64)  echo "amd64" ;;
        aarch64|arm64) echo "arm64" ;;
        armv7l)        echo "armv7" ;;
        *) die "不支持的架构: $(uname -m)" ;;
    esac
}

latest_version() {
    curl -fsSL --max-time 15 \
        "https://api.github.com/repos/SagerNet/sing-box/releases" \
        | jq -r '[.[] | select(.draft==false)][0].tag_name' 2>/dev/null | sed 's/^v//'
}

current_version() {
    [[ -x "$SB_BIN" ]] && "$SB_BIN" version 2>/dev/null | head -1 | awk '{print $3}'
}

install_singbox() {
    local ver="$1" arch; arch=$(get_arch)
    local pkg="sing-box-${ver}-linux-${arch}"
    local url="https://github.com/SagerNet/sing-box/releases/download/v${ver}/${pkg}.tar.gz"
    info "下载 sing-box ${ver} (${arch})"
    local tmp; tmp=$(mktemp -d)
    if ! curl -fsSL --max-time 120 "$url" -o "$tmp/sb.tar.gz"; then
        rm -rf "$tmp"; die "下载失败: $url"
    fi
    tar -xzf "$tmp/sb.tar.gz" -C "$tmp" || { rm -rf "$tmp"; die "解压失败"; }
    mkdir -p "$SB_DIR"
    [[ -x "$SB_BIN" ]] && cp "$SB_BIN" "${SB_BIN}.bak.$(date +%Y%m%d%H%M)"
    install -m 755 "$tmp/$pkg/sing-box" "$SB_BIN" || { rm -rf "$tmp"; die "安装失败"; }
    rm -rf "$tmp"
    ok "sing-box ${ver} 已安装"
}

setup_service() {
    cat > /etc/systemd/system/sing-box.service <<EOF
[Unit]
Description=sing-box service
After=network-online.target nss-lookup.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$SB_BIN run -c $SB_CONF
Restart=on-failure
RestartSec=5s
LimitNOFILE=1048576
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable sing-box >/dev/null 2>&1
}

tune_sysctl() {
    cat > /etc/sysctl.d/99-singbox.conf <<'EOF'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = 8388608
net.core.wmem_max = 8388608
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.ipv4.tcp_rmem = 4096 87380 8388608
net.ipv4.tcp_wmem = 4096 65536 8388608
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mtu_probing = 1
net.core.somaxconn = 4096
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_max_syn_backlog = 8192
EOF
    sysctl --system >/dev/null 2>&1
    ok "已应用 BBR + 网络调优"
}

# ─────────────────────────────────────────────
# 快捷命令 s
# ─────────────────────────────────────────────
SELF_PATH="$SB_ETC/manage.sh"

install_shortcut() {
    local src="${BASH_SOURCE[0]}"
    [[ -f "$src" ]] || return 0
    mkdir -p "$SB_ETC"
    if ! cmp -s "$src" "$SELF_PATH" 2>/dev/null; then
        cp "$src" "$SELF_PATH"
        chmod 700 "$SELF_PATH"
    fi
    # 同步面板文件（若与脚本同目录）
    local pdir; pdir="$(cd "$(dirname "$src")" && pwd)"
    [[ -f "$pdir/singbox-panel.py" && ! -f "$SB_ETC/panel.py" ]] && \
        cp "$pdir/singbox-panel.py" "$SB_ETC/panel.py" && chmod 700 "$SB_ETC/panel.py"

    cat > /usr/local/bin/s <<EOF
#!/bin/bash
exec bash "$SELF_PATH" "\$@"
EOF
    chmod 755 /usr/local/bin/s
}

# ─────────────────────────────────────────────
# 通用工具
# ─────────────────────────────────────────────
ask() {  # ask <提示> <默认值> -> ANS
    local p="$1" d="$2" v
    read -rp "$(echo -e "${BLUE}?${NC} ${p} [${d}]: ")" v
    ANS="${v:-$d}"
}
rand_hex() { openssl rand -hex "${1:-8}"; }
b64()      { printf '%s' "$1" | base64 -w0 2>/dev/null || printf '%s' "$1" | base64; }
get_ip()   { curl -s4 --max-time 8 ifconfig.me || curl -s4 --max-time 8 ip.sb; }

# ─────────────────────────────────────────────
# acme.sh
# ─────────────────────────────────────────────
ACME_HOME="/root/.acme.sh"

find_acme() {
    local p
    for p in "$ACME_HOME/acme.sh" /root/acme.sh/acme.sh /usr/local/bin/acme.sh; do
        [[ -x "$p" ]] && { echo "$p"; return 0; }
    done
    return 1
}

install_acme() {
    local email="$1" out
    info "安装 acme.sh"
    # 方式一：官方一键源（标准调用形式）
    out=$(HOME=/root curl -fsSL https://get.acme.sh 2>&1 | HOME=/root sh -s email="$email" 2>&1)
    find_acme >/dev/null && { ok "acme.sh 安装成功"; return 0; }

    warn "官方源失败，尝试 GitHub 源"
    out=$(cd /tmp && HOME=/root curl -fsSL \
        https://raw.githubusercontent.com/acmesh-official/acme.sh/master/acme.sh -o acme.sh 2>&1 \
        && chmod +x acme.sh \
        && HOME=/root ./acme.sh --install --home "$ACME_HOME" --accountemail "$email" 2>&1)
    find_acme >/dev/null && { ok "acme.sh 安装成功 (GitHub 源)"; return 0; }

    err "acme.sh 安装失败，最后输出："
    echo "$out" | tail -12 | sed 's/^/    /'
    echo
    warn "常见原因：服务器无法访问 get.acme.sh / GitHub，或缺少 socat"
    warn "可手动安装后重试： curl https://get.acme.sh | sh -s email=$email"
    return 1
}

# ─────────────────────────────────────────────
# 订阅
# ─────────────────────────────────────────────
SUB_TOKEN=""; SUB_PORT="8080"

load_sub_meta() {
    if [[ -f "$PANEL_CFG_F" ]]; then
        SUB_TOKEN=$(jq -r '.sub_token // empty' "$PANEL_CFG_F" 2>/dev/null)
        SUB_PORT=$(jq -r '.sub_port // 8080' "$PANEL_CFG_F" 2>/dev/null)
    fi
    [[ -z "$SUB_TOKEN" ]] && SUB_TOKEN=$(rand_hex 16)
    [[ -z "$SUB_PORT" || "$SUB_PORT" == "null" ]] && SUB_PORT="8080"
}

rebuild_sub() {
    load_sub_meta
    mkdir -p "$SUB_DIR"
    local plain; plain=$(list_uris)
    find "$SUB_DIR" -maxdepth 1 -type f ! -name "$SUB_TOKEN" -delete 2>/dev/null
    printf '%s' "$(b64 "$plain")" > "$SUB_DIR/$SUB_TOKEN"
    chmod 644 "$SUB_DIR/$SUB_TOKEN"
}

setup_sub_service() {
    # 订阅已合并进面板进程，清理历史遗留的独立服务
    if [[ -f /etc/systemd/system/singbox-sub.service ]]; then
        systemctl disable --now singbox-sub >/dev/null 2>&1
        rm -f /etc/systemd/system/singbox-sub.service
        systemctl daemon-reload
        info "订阅服务已合并进面板，独立服务已移除"
    fi
    systemctl is-active --quiet singbox-panel || systemctl restart singbox-panel 2>/dev/null
}

show_sub() {
    rebuild_sub
    setup_sub_service
    title "订阅链接"
    echo -e "  ${BOLD}${GREEN}http://$(get_ip):${SUB_PORT}/${SUB_TOKEN}${NC}"
    echo
    local ncnt; ncnt=$(list_uris | grep -c . || true)
    echo "  节点数: ${ncnt:-0}"
    warn "订阅为明文 HTTP，token 即密码，勿外泄"
    warn "如有防火墙请放行: ufw allow ${SUB_PORT}/tcp"
}

# ─────────────────────────────────────────────
# 节点信息（数据源: 面板的 nodemeta.json）
# ─────────────────────────────────────────────
NODE_META="$SB_ETC/nodemeta.json"

list_uris() {   # 输出所有分享链接，每行一条
    [[ -f "$NODE_META" ]] || return 0
    jq -r 'to_entries[]|select(.value.uri!=null and .value.uri!="")|.value.uri' "$NODE_META" 2>/dev/null
}

show_links() {
    title "节点分享链接"
    local n=0
    if [[ -f "$NODE_META" ]]; then
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            local tag name uri
            tag=$(echo "$line" | jq -r .k); name=$(echo "$line" | jq -r .n); uri=$(echo "$line" | jq -r .u)
            echo -e "  ${BOLD}${name}${NC}  ${BLUE}[$tag]${NC}"
            echo -e "  ${GREEN}${uri}${NC}"; echo
            ((n++))
        done < <(jq -c 'to_entries[]|{k:.key,n:(.value.name//.key),u:(.value.uri//"")}' "$NODE_META" 2>/dev/null)
    fi
    [[ $n -eq 0 ]] && { warn "暂无节点，请在 Web 面板创建"; return; }
    show_sub
}

# ─────────────────────────────────────────────
# 配置管理
# ─────────────────────────────────────────────
init_config() {
    mkdir -p "$SB_ETC" "$CERT_DIR" "$SUB_DIR"
    [[ -f "$SB_CONF" ]] && return 0
    jq -n '{
      log:{level:"warn", timestamp:true},
      inbounds:[],
      outbounds:[{type:"direct", tag:"direct"}],
      route:{rules:[{action:"sniff"}], final:"direct"}
    }' > "$SB_CONF"
}


del_node() {
    title "删除节点"
    mapfile -t tags < <(jq -r '.inbounds[]?.tag' "$SB_CONF" 2>/dev/null)
    [[ ${#tags[@]} -eq 0 ]] && { warn "没有节点"; return 0; }
    local i=1
    for t in "${tags[@]}"; do echo "  $i) $t"; ((i++)); done
    read -rp "$(echo -e "${BLUE}?${NC} 删除第几个 (回车取消): ")" n
    [[ -z "$n" ]] && return 0
    local tag="${tags[$((n-1))]}"
    [[ -z "$tag" ]] && { err "无效选择"; return 1; }
    local tmp; tmp=$(mktemp)
    jq --arg t "$tag" '
        (.inbounds |= map(select(.tag != $t)))
        | (.route.rules |= map(select((.inbound? // []) | index($t) | not)))' \
        "$SB_CONF" > "$tmp" && mv "$tmp" "$SB_CONF"
    if [[ -f "$NODE_META" ]]; then
        jq --arg t "$tag" 'del(.[$t])' "$NODE_META" > "$tmp" && mv "$tmp" "$NODE_META"
    fi
    systemctl restart sing-box
    rebuild_sub
    ok "已删除 $tag"
}

do_upgrade() {
    title "版本管理"
    local cur latest pinned
    cur=$(current_version); latest=$(latest_version)
    [[ -f "$SB_ETC/version.pin" ]] && pinned=$(cat "$SB_ETC/version.pin")
    echo "  当前版本: ${GREEN}${cur:-未安装}${NC}"
    echo "  最新版本: ${latest:-获取失败}"
    [[ -n "$pinned" ]] && echo -e "  ${YELLOW}已锁定: $pinned${NC} (不会自动升级)"
    echo
    echo "  1) 升级到最新版 (${latest:-?})"
    echo "  2) 安装指定版本 (如 1.14.0-beta.7)"
    echo "  3) 锁定当前版本 / 解除锁定"
    echo "  0) 返回"
    read -rp "$(echo -e "${BLUE}?${NC} 选择: ")" vc

    local target=""
    case "$vc" in
        1) [[ -z "$latest" ]] && { err "无法获取最新版本"; return 1; }
           [[ "$cur" == "$latest" ]] && { ok "已是最新版本"; return 0; }
           target="$latest" ;;
        2) ask "版本号 (不带 v 前缀)" "1.14.0-beta.7"
           target="${ANS#v}" ;;
        3) if [[ -n "$pinned" ]]; then
               rm -f "$SB_ETC/version.pin"; ok "已解除版本锁定"
           else
               echo "$cur" > "$SB_ETC/version.pin"; ok "已锁定在 $cur"
           fi
           return 0 ;;
        *) return 0 ;;
    esac

    [[ -z "$target" ]] && return 0
    if [[ -n "$pinned" && "$target" != "$pinned" ]]; then
        warn "当前锁定在 $pinned"
        read -rp "$(echo -e "${BLUE}?${NC} 仍要切换到 $target? [y/N]: ")" f
        [[ ! "$f" =~ ^[Yy]$ ]] && return 0
        rm -f "$SB_ETC/version.pin"
    fi
    read -rp "$(echo -e "${BLUE}?${NC} 安装 $target? [Y/n]: ")" yn
    [[ "$yn" =~ ^[Nn]$ ]] && return 0
    systemctl stop sing-box 2>/dev/null
    install_singbox "$target"
    if [[ -f "$SB_CONF" ]] && ! "$SB_BIN" check -c "$SB_CONF" 2>/tmp/sb_err; then
        err "新版本校验配置失败:"; cat /tmp/sb_err
        warn "可回滚: cp ${SB_BIN}.bak.* $SB_BIN && systemctl restart sing-box"
    fi
    systemctl start sing-box
    systemctl is-active --quiet sing-box && ok "升级完成" || err "启动失败: journalctl -u sing-box"
}

# ─────────────────────────────────────────────
# 出站管理（中转 → 落地）
# ─────────────────────────────────────────────
add_socks_out() {
    title "添加 SOCKS5 出站（落地）"
    echo "  格式: ip:端口:账号:密码   (无认证填 ip:端口)"
    ask "落地信息" ""
    local raw="$ANS"
    [[ -z "$raw" ]] && { err "不能为空"; return 1; }

    local ip port user pass
    IFS=':' read -r ip port user pass <<< "$raw"
    if [[ -z "$ip" || -z "$port" ]] || ! [[ "$port" =~ ^[0-9]+$ ]]; then
        err "格式错误，应为 ip:端口:账号:密码"; return 1
    fi

    ask "出站名称" "landing-${ip##*.}"
    local tag="$ANS"
    if jq -e --arg t "$tag" '.outbounds[]|select(.tag==$t)' "$SB_CONF" >/dev/null 2>&1; then
        err "名称 $tag 已存在"; return 1
    fi

    local ob
    if [[ -n "$user" ]]; then
        ob=$(jq -n --arg t "$tag" --arg s "$ip" --argjson p "$port" \
                   --arg u "$user" --arg w "$pass" '
            {type:"socks", tag:$t, server:$s, server_port:$p,
             version:"5", username:$u, password:$w, udp_over_tcp:false}')
    else
        ob=$(jq -n --arg t "$tag" --arg s "$ip" --argjson p "$port" '
            {type:"socks", tag:$t, server:$s, server_port:$p, version:"5", udp_over_tcp:false}')
    fi

    local tmp; tmp=$(mktemp)
    jq --argjson o "$ob" '.outbounds += [$o]' "$SB_CONF" > "$tmp" && mv "$tmp" "$SB_CONF"

    if ! "$SB_BIN" check -c "$SB_CONF" 2>/tmp/sb_err; then
        err "配置校验失败，已回滚:"; cat /tmp/sb_err
        jq --arg t "$tag" 'del(.outbounds[]|select(.tag==$t))' "$SB_CONF" > "$tmp" && mv "$tmp" "$SB_CONF"
        return 1
    fi
    systemctl restart sing-box
    ok "出站 $tag 已添加 (${ip}:${port})"
    warn "接下来用「绑定节点出站」把某个节点指过去"
}

bind_outbound() {
    title "绑定：节点 → 出站"
    mapfile -t ins < <(jq -r '.inbounds[]?.tag' "$SB_CONF" 2>/dev/null)
    mapfile -t outs < <(jq -r '.outbounds[]?|select(.type!="direct")|.tag' "$SB_CONF" 2>/dev/null)
    [[ ${#ins[@]} -eq 0 ]] && { warn "还没有节点，先创建节点"; return 0; }
    [[ ${#outs[@]} -eq 0 ]] && { warn "还没有出站，先添加 SOCKS5 出站"; return 0; }

    echo "  ${BOLD}入站节点:${NC}"
    local i=1
    for t in "${ins[@]}"; do
        local cur
        cur=$(jq -r --arg t "$t" '.route.rules[]?|select(.inbound?|index($t))|.outbound' "$SB_CONF" 2>/dev/null | head -1)
        echo "    $i) $t  →  ${cur:-direct(默认)}"; ((i++))
    done
    read -rp "$(echo -e "${BLUE}?${NC} 选择节点 (回车取消): ")" n
    [[ -z "$n" ]] && return 0
    local intag="${ins[$((n-1))]}"
    [[ -z "$intag" ]] && { err "无效选择"; return 1; }

    echo "  ${BOLD}可用出站:${NC}"
    i=1
    for t in "${outs[@]}"; do echo "    $i) $t"; ((i++)); done
    echo "    0) direct (取消绑定，走本机直连)"
    read -rp "$(echo -e "${BLUE}?${NC} 选择出站: ")" m
    [[ -z "$m" ]] && return 0

    local tmp; tmp=$(mktemp)
    # 先移除该入站已有的绑定
    jq --arg t "$intag" '.route.rules |= map(select((.inbound? // []) | index($t) | not))' \
        "$SB_CONF" > "$tmp" && mv "$tmp" "$SB_CONF"

    if [[ "$m" == "0" ]]; then
        systemctl restart sing-box; ok "$intag 已恢复直连"; return 0
    fi
    local outtag="${outs[$((m-1))]}"
    [[ -z "$outtag" ]] && { err "无效选择"; return 1; }

    # 绑定规则插到 sniff 之后
    jq --arg i "$intag" --arg o "$outtag" '
        .route.rules |= ( .[0:1] + [{inbound:[$i], outbound:$o}] + .[1:] )' \
        "$SB_CONF" > "$tmp" && mv "$tmp" "$SB_CONF"

    if ! "$SB_BIN" check -c "$SB_CONF" 2>/tmp/sb_err; then
        err "配置校验失败:"; cat /tmp/sb_err; return 1
    fi
    systemctl restart sing-box
    ok "$intag  →  $outtag  (该节点全部流量走此出站)"
}

test_outbound() {
    title "测试出站"
    mapfile -t outs < <(jq -r '.outbounds[]?|select(.type=="socks")|"\(.tag) \(.server) \(.server_port)"' "$SB_CONF" 2>/dev/null)
    [[ ${#outs[@]} -eq 0 ]] && { warn "没有 SOCKS 出站"; return 0; }
    for line in "${outs[@]}"; do
        local tag srv port; read -r tag srv port <<< "$line"
        printf "  %-20s " "$tag"
        if timeout 5 bash -c "</dev/tcp/$srv/$port" 2>/dev/null; then
            local u p
            u=$(jq -r --arg t "$tag" '.outbounds[]|select(.tag==$t)|.username // ""' "$SB_CONF")
            p=$(jq -r --arg t "$tag" '.outbounds[]|select(.tag==$t)|.password // ""' "$SB_CONF")
            local auth=""; [[ -n "$u" ]] && auth="${u}:${p}@"
            local exit_ip
            exit_ip=$(curl -s --max-time 8 --socks5-hostname "${auth}${srv}:${port}" https://api.ipify.org 2>/dev/null)
            if [[ -n "$exit_ip" ]]; then
                echo -e "${GREEN}可用${NC}  出口 IP: ${BOLD}${exit_ip}${NC}"
            else
                echo -e "${YELLOW}端口通但代理未响应${NC} (检查账号密码)"
            fi
        else
            echo -e "${RED}不可达${NC} (${srv}:${port})"
        fi
    done
}

del_outbound() {
    title "删除出站"
    mapfile -t outs < <(jq -r '.outbounds[]?|select(.type!="direct")|.tag' "$SB_CONF" 2>/dev/null)
    [[ ${#outs[@]} -eq 0 ]] && { warn "没有可删除的出站"; return 0; }
    local i=1
    for t in "${outs[@]}"; do echo "  $i) $t"; ((i++)); done
    read -rp "$(echo -e "${BLUE}?${NC} 删除第几个 (回车取消): ")" n
    [[ -z "$n" ]] && return 0
    local tag="${outs[$((n-1))]}"
    [[ -z "$tag" ]] && { err "无效选择"; return 1; }
    local tmp; tmp=$(mktemp)
    jq --arg t "$tag" '
        (.outbounds |= map(select(.tag != $t)))
        | (.route.rules |= map(select(.outbound != $t)))
        | (if .route.final == $t then .route.final = "direct" else . end)' \
        "$SB_CONF" > "$tmp" && mv "$tmp" "$SB_CONF"
    systemctl restart sing-box
    ok "已删除出站 $tag（相关绑定一并移除）"
}

outbound_menu() {
    while true; do
        title "出站管理（中转 → 落地）"
        mapfile -t obs < <(jq -r '.outbounds[]?|select(.type!="direct")|"  - \(.tag)  [\(.type)]  \(.server // "-"):\(.server_port // "-")"' "$SB_CONF" 2>/dev/null)
        if [[ ${#obs[@]} -gt 0 ]]; then
            echo "  ${BOLD}已配置出站:${NC}"; printf '%s\n' "${obs[@]}"
        else
            echo "  (暂无出站，所有节点走本机直连)"
        fi
        echo
        echo "  ${BOLD}当前绑定:${NC}"
        jq -r '.route.rules[]?|select(.inbound)|"    \(.inbound[0])  →  \(.outbound)"' "$SB_CONF" 2>/dev/null || true
        cat <<'EOF'

  1) 添加 SOCKS5 出站（落地）
  2) 绑定节点 → 出站
  3) 测试出站（显示出口 IP）
  4) 删除出站
  0) 返回主菜单
EOF
        read -rp "$(echo -e "${BLUE}?${NC} 选择: ")" c
        case "$c" in
            1) add_socks_out ;;
            2) bind_outbound ;;
            3) test_outbound ;;
            4) del_outbound ;;
            0) return 0 ;;
            *) err "无效选择" ;;
        esac
        echo; read -rp "按回车继续..."
    done
}

# ─────────────────────────────────────────────
# Web 面板
# ─────────────────────────────────────────────
PANEL_PY="$SB_ETC/panel.py"
PANEL_CFG_F="$SB_ETC/panel.json"

panel_installed() { [[ -f "$PANEL_PY" ]]; }

install_panel() {
    title "安装 Web 面板"
    if [[ ! -f "$PANEL_PY" ]]; then
        if [[ -f "$(dirname "$0")/singbox-panel.py" ]]; then
            cp "$(dirname "$0")/singbox-panel.py" "$PANEL_PY"
        else
            err "找不到 singbox-panel.py，请与本脚本放在同一目录"; return 1
        fi
    fi
    chmod 700 "$PANEL_PY"

    local pw pw2
    while true; do
        read -rsp "$(echo -e "${BLUE}?${NC} 设置面板密码: ")" pw; echo
        [[ ${#pw} -lt 6 ]] && { err "至少 6 位"; continue; }
        read -rsp "$(echo -e "${BLUE}?${NC} 再输一次: ")" pw2; echo
        [[ "$pw" == "$pw2" ]] && break || err "两次不一致"
    done

    ask "面板端口" "2095"; local pport="$ANS"
    echo
    echo "  监听方式:"
    echo "    1) 仅本机 127.0.0.1  (推荐，用 SSH 隧道访问，不暴露公网)"
    echo "    2) 公网 0.0.0.0      (方便但会被扫描)"
    read -rp "$(echo -e "${BLUE}?${NC} 选择 [1]: ")" lm
    local host="127.0.0.1"; [[ "$lm" == "2" ]] && host="0.0.0.0"

    ask "订阅服务端口" "8080"; local sport="$ANS"
    ask "面板访问路径 (防扫描，回车用随机)" "$(rand_hex 8)"
    local ppath="${ANS#/}"; ppath="${ppath%/}"

    local salt hash token
    salt=$(rand_hex 8)
    hash=$(printf '%s' "${pw}${salt}" | sha256sum | awk '{print $1}')
    token=$(rand_hex 16)
    jq -n --arg s "$salt" --arg h "$hash" --arg ho "$host" --arg pa "$ppath" \
          --argjson p "$pport" --argjson sp "$sport" --arg t "$token" \
        '{salt:$s, pwhash:$h, host:$ho, port:$p, path:$pa, sub_port:$sp, sub_token:$t}' > "$PANEL_CFG_F"
    chmod 600 "$PANEL_CFG_F"

    cat > /etc/systemd/system/singbox-panel.service <<EOF
[Unit]
Description=sing-box web panel
After=network.target

[Service]
Type=simple
Environment=HOME=/root
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
WorkingDirectory=/root
ExecStart=$(command -v python3) $PANEL_PY
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable singbox-panel >/dev/null 2>&1
    systemctl restart singbox-panel
    sleep 1

    rebuild_sub
    setup_sub_service "$sport"

    if systemctl is-active --quiet singbox-panel; then
        ok "面板已启动"
        panel_info
    else
        err "面板启动失败:"; journalctl -u singbox-panel -n 20 --no-pager
    fi
}

panel_info() {
    [[ ! -f "$PANEL_CFG_F" ]] && { warn "面板未安装"; return 1; }
    local host port sport ip dom path scheme addr
    host=$(jq -r '.host // "127.0.0.1"' "$PANEL_CFG_F")
    port=$(jq -r '.port // 2095' "$PANEL_CFG_F")
    sport=$(jq -r '.sub_port // 8080' "$PANEL_CFG_F")
    dom=$(jq -r '.tls_domain // ""' "$PANEL_CFG_F")
    path=$(jq -r '.path // ""' "$PANEL_CFG_F")
    [[ -n "$path" ]] && path="/${path#/}"
    ip=$(get_ip)

    title "Web 面板信息"
    if [[ -n "$dom" ]]; then
        scheme="https"; addr="$dom"
    elif [[ "$host" == "0.0.0.0" || "$host" == "::" ]]; then
        scheme="http"; addr="$ip"          # 监听全网卡时用公网 IP 访问
    else
        scheme="http"; addr="$host"
    fi

    echo -e "  ${BOLD}访问地址${NC}"
    if [[ "$host" == "127.0.0.1" && -z "$dom" ]]; then
        echo -e "    仅本机监听，先在你电脑上建 SSH 隧道:"
        echo -e "    ${BLUE}ssh -L ${port}:127.0.0.1:${port} root@${ip}${NC}"
        echo -e "    再浏览器打开: ${GREEN}${BOLD}http://127.0.0.1:${port}${path}${NC}"
    else
        echo -e "    ${GREEN}${BOLD}${scheme}://${addr}:${port}${path}${NC}"
        [[ "$host" != "127.0.0.1" ]] && warn "面板监听公网，建议: ufw allow from 你的IP to any port ${port} proto tcp"
    fi

    echo
    echo -e "  ${BOLD}配置详情${NC}"
    if [[ "$host" == "0.0.0.0" ]]; then
        echo -e "    监听地址   : ${host}:${port}  ${YELLOW}(全网卡)${NC}"
    else
        echo -e "    监听地址   : ${host}:${port}  ${GREEN}(仅本机)${NC}"
    fi
    echo -e "    访问路径   : ${path:-/ (未设置，建议设置以防扫描)}"
    echo -e "    HTTPS      : ${dom:-未启用}"
    echo -e "    登录密码   : ${YELLOW}已加密存储，忘记可用菜单重置${NC}"
    echo
    echo -e "  ${BOLD}订阅${NC}"
    local tok subsch subhost
    tok=$(jq -r '.sub_token // ""' "$PANEL_CFG_F")
    if [[ -n "$dom" ]]; then subsch="https"; subhost="$dom"; else subsch="http"; subhost="$ip"; fi
    echo -e "    ${GREEN}${subsch}://${subhost}:${sport}/${tok}${NC}"
    local ncnt; ncnt=$(list_uris | grep -c . || true)
    echo -e "    节点数     : ${ncnt:-0}"
}

setup_domain() {
    [[ ! -f "$PANEL_CFG_F" ]] && { warn "请先安装 Web 面板"; return 1; }
    title "一键配置域名访问"
    echo "  将完成: 申请证书 → 面板改用 HTTPS 域名 → 订阅链接同步用域名"
    echo
    local cur; cur=$(jq -r '.tls_domain // ""' "$PANEL_CFG_F")
    [[ -n "$cur" ]] && echo -e "  当前已配置: ${GREEN}${cur}${NC}\n"

    ask "域名" "$cur"
    local dom="$ANS"
    [[ -z "$dom" ]] && { warn "已取消"; return 0; }

    # 1) 校验解析
    local ip myip
    myip=$(get_ip)
    ip=$(getent ahostsv4 "$dom" 2>/dev/null | head -1 | awk '{print $1}')
    if [[ -z "$ip" ]]; then
        err "域名无法解析，请先添加 A 记录: ${dom} → ${myip}"; return 1
    fi
    if [[ "$ip" != "$myip" ]]; then
        err "域名解析到 ${ip}，本机公网 IP 是 ${myip}"
        echo "  请把 A 记录改为 ${myip}，DNS 生效后再试"
        return 1
    fi
    ok "解析正确: ${dom} → ${myip}"

    # 2) 证书：优先复用，避免浪费 Let's Encrypt 配额
    mkdir -p "$CERT_DIR/$dom"
    local need=1
    if [[ -s "$CERT_DIR/$dom/fullchain.pem" ]] && \
       openssl x509 -in "$CERT_DIR/$dom/fullchain.pem" -noout -checkend 604800 >/dev/null 2>&1; then
        ok "已有有效证书，直接复用"; need=0
    else
        local acmebin; acmebin=$(find_acme) || acmebin=""
        if [[ -n "$acmebin" ]]; then
            for d in "$ACME_HOME/${dom}_ecc" "$ACME_HOME/${dom}"; do
                if [[ -s "$d/fullchain.cer" ]] && \
                   openssl x509 -in "$d/fullchain.cer" -noout -checkend 604800 >/dev/null 2>&1; then
                    local ecc=""; [[ "$d" == *_ecc ]] && ecc="--ecc"
                    HOME=/root "$acmebin" --install-cert -d "$dom" $ecc \
                        --fullchain-file "$CERT_DIR/$dom/fullchain.pem" \
                        --key-file "$CERT_DIR/$dom/privkey.pem" \
                        --reloadcmd "systemctl restart sing-box; systemctl restart singbox-panel" >/dev/null 2>&1
                    ok "复用 acme.sh 本地证书（未消耗签发次数）"; need=0; break
                fi
            done
        fi
    fi

    if [[ $need -eq 1 ]]; then
        # 80 端口检查
        local who; who=$(ss -ltnp 2>/dev/null | grep ':80 ' | head -1)
        if [[ -n "$who" && "$who" != *sing-box* ]]; then
            err "80 端口被占用，请先停止:"; echo "  $who"; return 1
        fi
        local acmebin; acmebin=$(find_acme) || acmebin=""
        if [[ -z "$acmebin" ]]; then
            install_acme "admin@${dom}" || return 1
            acmebin=$(find_acme) || { err "acme.sh 仍不可用"; return 1; }
        fi

        info "申请证书中（约 30 秒）"
        systemctl stop sing-box 2>/dev/null
        HOME=/root "$acmebin" --set-default-ca --server letsencrypt >/dev/null 2>&1
        local iss rc
        iss=$(HOME=/root "$acmebin" --issue -d "$dom" --standalone --keylength ec-256 2>&1); rc=$?
        if [[ $rc -ne 0 ]]; then
            # 撞 Let's Encrypt 限流则自动换 ZeroSSL
            if grep -q "rateLimited" <<<"$iss"; then
                warn "Let's Encrypt 限流，改用 ZeroSSL"
                HOME=/root "$acmebin" --set-default-ca --server zerossl >/dev/null 2>&1
                iss=$(HOME=/root "$acmebin" --issue -d "$dom" --standalone --keylength ec-256 2>&1); rc=$?
            fi
        fi
        if [[ $rc -ne 0 ]]; then
            systemctl start sing-box 2>/dev/null
            err "证书申请失败："
            echo "$iss" | tail -12 | sed 's/^/    /'
            return 1
        fi
        HOME=/root "$acmebin" --install-cert -d "$dom" --ecc \
            --fullchain-file "$CERT_DIR/$dom/fullchain.pem" \
            --key-file "$CERT_DIR/$dom/privkey.pem" \
            --reloadcmd "systemctl restart sing-box; systemctl restart singbox-panel" >/dev/null 2>&1
        systemctl start sing-box 2>/dev/null
        ok "证书已签发"
    fi

    [[ ! -s "$CERT_DIR/$dom/fullchain.pem" ]] && { err "证书文件缺失，配置中止"; return 1; }

    # 3) 写入面板配置
    local tmp; tmp=$(mktemp)
    jq --arg d "$dom" '.tls_domain=$d | .host="0.0.0.0"' "$PANEL_CFG_F" > "$tmp" && mv "$tmp" "$PANEL_CFG_F"
    chmod 600 "$PANEL_CFG_F"
    systemctl restart singbox-panel
    sleep 1
    ok "域名访问已启用"
    echo
    panel_info
    echo
    warn "客户端里的订阅地址需要改成上面的新地址"
    warn "面板已监听公网，建议: ufw allow from 你的IP to any port $(jq -r .port "$PANEL_CFG_F") proto tcp"
}

panel_set_path() {
    [[ ! -f "$PANEL_CFG_F" ]] && { warn "面板未安装"; return 1; }
    local cur; cur=$(jq -r '.path // ""' "$PANEL_CFG_F")
    title "设置面板路径"
    echo "  当前: ${cur:-无（根路径）}"
    echo "  设置后必须带路径才能访问，可有效防止被扫描器发现"
    echo
    echo "  1) 自动生成随机路径 (推荐)"
    echo "  2) 手动输入"
    echo "  3) 清除路径"
    echo "  0) 返回"
    read -rp "$(echo -e "${BLUE}?${NC} 选择: ")" c
    local np=""
    case "$c" in
        1) np=$(rand_hex 8) ;;
        2) ask "路径 (不含斜杠)" "$(rand_hex 6)"; np="${ANS#/}"; np="${np%/}" ;;
        3) np="" ;;
        *) return 0 ;;
    esac
    local tmp; tmp=$(mktemp)
    jq --arg p "$np" '.path=$p' "$PANEL_CFG_F" > "$tmp" && mv "$tmp" "$PANEL_CFG_F"
    chmod 600 "$PANEL_CFG_F"
    systemctl restart singbox-panel
    ok "路径已更新"
    panel_info
}

panel_reset_pw() {
    [[ ! -f "$PANEL_CFG_F" ]] && { warn "面板未安装"; return 1; }
    local pw pw2
    while true; do
        read -rsp "$(echo -e "${BLUE}?${NC} 新密码: ")" pw; echo
        [[ ${#pw} -lt 6 ]] && { err "至少 6 位"; continue; }
        read -rsp "$(echo -e "${BLUE}?${NC} 再输一次: ")" pw2; echo
        [[ "$pw" == "$pw2" ]] && break || err "两次不一致"
    done
    local salt hash tmp
    salt=$(rand_hex 8)
    hash=$(printf '%s' "${pw}${salt}" | sha256sum | awk '{print $1}')
    tmp=$(mktemp)
    jq --arg s "$salt" --arg h "$hash" '.salt=$s|.pwhash=$h' "$PANEL_CFG_F" > "$tmp" && mv "$tmp" "$PANEL_CFG_F"
    chmod 600 "$PANEL_CFG_F"
    systemctl restart singbox-panel
    ok "密码已重置，所有登录会话失效"
}

panel_menu() {
    while true; do
        title "Web 面板"
        if panel_installed; then
            local st="停止"; systemctl is-active --quiet singbox-panel && st="${GREEN}运行中${NC}"
            echo -e "  状态: $st"
            panel_info
        else
            echo "  未安装"
        fi
        cat <<'EOF'

  1) 查看完整信息 (地址 / 路径 / 订阅)
  2) 一键配置域名访问 (证书+HTTPS+订阅) ★
  3) 设置访问路径 (防扫描)
  4) 重置登录密码
  ─────────────────────────
  ─────────────────────────
  5) 安装 / 重装面板
  6) 重启面板
  7) 停止并卸载面板
  0) 返回
EOF
        read -rp "$(echo -e "${BLUE}?${NC} 选择: ")" c
        case "$c" in
            1) panel_info ;;
            2) setup_domain ;;
            3) panel_set_path ;;
            4) panel_reset_pw ;;
            5) install_panel ;;
            6) systemctl restart singbox-panel && ok "已重启" ;;
            7) systemctl disable --now singbox-panel >/dev/null 2>&1
               rm -f /etc/systemd/system/singbox-panel.service "$PANEL_PY"
               systemctl daemon-reload; ok "已卸载" ;;
            0) return 0 ;;
            *) err "无效选择" ;;
        esac
        echo; read -rp "按回车继续..."
    done
}

do_uninstall() {
    title "完全卸载"
    echo "  将删除: 服务 / 程序 / 配置 / 节点 / 证书 / 快捷命令 / BBR调优 / 端口跳跃规则"
    read -rp "$(echo -e "${RED}确认卸载? 输入 yes: ${NC}")" c
    [[ "$c" != "yes" ]] && { warn "已取消"; return 0; }

    local bk="/root/singbox-backup-$(date +%Y%m%d%H%M).tar.gz"
    tar -czf "$bk" -C / etc/sing-box 2>/dev/null && ok "配置已备份到 $bk"

    for s in sing-box singbox-panel singbox-sub; do
        systemctl disable --now "$s" >/dev/null 2>&1
        rm -f "/etc/systemd/system/${s}.service"
    done
    systemctl daemon-reload; systemctl reset-failed >/dev/null 2>&1

    local n=0 line
    while :; do
        line=$(iptables -t nat -L PREROUTING -n --line-numbers 2>/dev/null \
               | grep -E 'DNAT.*udp dpts:' | head -1 | awk '{print $1}')
        [[ -z "$line" ]] && break
        iptables -t nat -D PREROUTING "$line" 2>/dev/null || break
        ((n++)); [[ $n -gt 20 ]] && break
    done
    if [[ $n -gt 0 ]]; then
        command -v netfilter-persistent >/dev/null && netfilter-persistent save >/dev/null 2>&1
        ok "已清理 $n 条端口跳跃规则"
    fi

    rm -rf "$SB_DIR" "$SB_ETC" /usr/local/bin/s /etc/sysctl.d/99-singbox.conf
    sysctl --system >/dev/null 2>&1

    if [[ -d "$HOME/.acme.sh" ]]; then
        read -rp "$(echo -e "${BLUE}?${NC} 同时卸载 acme.sh 和证书? [y/N]: ")" a
        if [[ "$a" =~ ^[Yy]$ ]]; then
            "$HOME/.acme.sh/acme.sh" --uninstall >/dev/null 2>&1
            rm -rf "$HOME/.acme.sh"; ok "acme.sh 已卸载"
        fi
    fi

    echo; ok "卸载完成，配置备份: $bk"
    exit 0
}

show_status() {
    title "当前状态"
    echo -e "  sing-box 版本 : ${GREEN}$(current_version || echo 未安装)${NC}"
    if systemctl is-active --quiet sing-box; then
        echo -e "  运行状态      : ${GREEN}运行中${NC}"
    else
        echo -e "  运行状态      : ${RED}未运行${NC}"
    fi
    echo -e "  服务器 IP     : $(get_ip)"
    if [[ -f "$SB_CONF" ]]; then
        local c; c=$(jq '.inbounds|length' "$SB_CONF" 2>/dev/null)
        echo -e "  节点数量      : ${c:-0}"
        jq -r '.inbounds[]? | "     - \(.tag)  [\(.type)]  :\(.listen_port)"' "$SB_CONF" 2>/dev/null
    fi
}

main_menu() {
    while true; do
        show_status
        title "菜单"
        cat <<'EOF'
  1) Web 面板 (创建节点 / 出站 / 绑定)  ★
  2) 出站管理（中转 → 落地 IP）
  ─────────────────────────
  3) 查看节点链接 + 订阅链接
  4) 删除节点
  5) 版本管理 (升级 / 锁定)
  6) 重启 sing-box
  7) 查看日志
  ─────────────────────────
  9) 完全卸载 sing-box
  0) 退出
EOF
        read -rp "$(echo -e "${BLUE}?${NC} 选择: ")" c
        case "$c" in
            1) panel_menu ;;
            2) outbound_menu ;;
            3) show_links ;;
            4) del_node ;;
            5) do_upgrade ;;
            6) systemctl restart sing-box && ok "已重启" ;;
            7) journalctl -u sing-box -n 50 --no-pager ;;
            9) do_uninstall ;;
            0) exit 0 ;;
            *) err "无效选择" ;;
        esac
        echo; read -rp "按回车继续..."
    done
}

main() {
    ensure_deps
    install_shortcut
    if [[ ! -x "$SB_BIN" ]]; then
        title "首次安装"
        mkdir -p "$SB_ETC"
        local v; v=$(latest_version)
        [[ -z "$v" ]] && v="1.14.0-beta.7"
        info "检测到最新版本: $v"
        ask "安装版本 (回车用最新，也可手动指定)" "$v"
        v="${ANS#v}"
        install_singbox "$v"
        init_config
        setup_service
        tune_sysctl
        systemctl start sing-box
        rebuild_sub
        setup_sub_service "$SUB_PORT"
        ok "安装完成"
        echo
        ok "以后输入 ${BOLD}s${NC}${GREEN} 即可打开本菜单${NC}"
        echo
        read -rp "是否现在安装 Web 面板(创建节点用)? [Y/n]: " yn
        [[ ! "$yn" =~ ^[Nn]$ ]] && install_panel
    else
        init_config
        rebuild_sub
    fi
    main_menu
}

main "$@"
