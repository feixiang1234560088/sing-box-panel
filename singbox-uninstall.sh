#!/bin/bash
# sing-box 完全卸载脚本
set -o pipefail
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
ok(){ echo -e "${GREEN}[✓]${NC} $1"; }
info(){ echo -e "${BLUE}[*]${NC} $1"; }
warn(){ echo -e "${YELLOW}[!]${NC} $1"; }

[[ $EUID -ne 0 ]] && { echo "请用 root 运行"; exit 1; }

echo -e "${BOLD}━━━ sing-box 卸载 ━━━${NC}"
echo "将删除:"
echo "  - systemd 服务 (sing-box / singbox-panel / singbox-sub)"
echo "  - /usr/local/sing-box/  (程序)"
echo "  - /etc/sing-box/        (配置 / 节点 / 证书)"
echo "  - /usr/local/bin/s      (快捷命令)"
echo "  - /etc/sysctl.d/99-singbox.conf (BBR 调优)"
echo "  - 端口跳跃 iptables 规则"
echo
read -rp "$(echo -e "${RED}确认卸载? 输入 yes: ${NC}")" c
[[ "$c" != "yes" ]] && { echo "已取消"; exit 0; }

# 备份
if [[ -d /etc/sing-box ]]; then
    BK="/root/singbox-backup-$(date +%Y%m%d%H%M).tar.gz"
    tar -czf "$BK" -C / etc/sing-box 2>/dev/null && ok "配置已备份到 $BK"
fi

# 停止并删除服务
for s in sing-box singbox-panel singbox-sub; do
    systemctl disable --now "$s" >/dev/null 2>&1
    rm -f "/etc/systemd/system/${s}.service"
done
systemctl daemon-reload
systemctl reset-failed >/dev/null 2>&1
ok "服务已停止并移除"

# 清理端口跳跃规则
n=0
while iptables -t nat -L PREROUTING -n --line-numbers 2>/dev/null | grep -qE 'DNAT.*udp dpts:'; do
    line=$(iptables -t nat -L PREROUTING -n --line-numbers | grep -E 'DNAT.*udp dpts:' | head -1 | awk '{print $1}')
    [[ -z "$line" ]] && break
    iptables -t nat -D PREROUTING "$line" 2>/dev/null || break
    ((n++)); [[ $n -gt 20 ]] && break
done
[[ $n -gt 0 ]] && { command -v netfilter-persistent >/dev/null && netfilter-persistent save >/dev/null 2>&1; ok "已清理 $n 条端口跳跃规则"; }

# 删除文件
rm -rf /usr/local/sing-box
rm -rf /etc/sing-box
rm -f /usr/local/bin/s
rm -f /etc/sysctl.d/99-singbox.conf
sysctl --system >/dev/null 2>&1
ok "文件已删除"

# 证书
if [[ -d "$HOME/.acme.sh" ]]; then
    echo
    read -rp "$(echo -e "${BLUE}?${NC} 同时卸载 acme.sh 和所有证书? [y/N]: ")" a
    if [[ "$a" =~ ^[Yy]$ ]]; then
        "$HOME/.acme.sh/acme.sh" --uninstall >/dev/null 2>&1
        rm -rf "$HOME/.acme.sh"
        ok "acme.sh 已卸载"
    else
        warn "已保留 acme.sh (证书续期任务仍在 crontab)"
    fi
fi

echo
ok "卸载完成"
[[ -n "$BK" ]] && echo -e "  配置备份: ${BOLD}$BK${NC}"
