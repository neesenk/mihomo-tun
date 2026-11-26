#!/usr/bin/env bash
# 策略路由:tailnet 网段走 Tailscale,其余私有/100.x 网段走本地。
# 用法: ts-policy-routing.sh start|stop|status
set -u

# 格式: 优先级|目的网段|路由表   (必须小于 Tailscale 的 5270;5190~5203 不与其 5210/5230/5250/5270 冲突)
RULES=(
  "5190|100.81.1.0/24|52"          # 你的 tailnet 网段 -> Tailscale
  "5191|100.100.100.100/32|52"     # MagicDNS -> Tailscale
  "5200|100.0.0.0/8|main"          # 其余 100.x -> 本地
  "5201|10.0.0.0/8|main"
  "5202|192.168.0.0/16|main"
  "5203|172.16.0.0/12|main"
)

# 可选配置 /etc/default/ts-policy-routing
#   LAN_IFACE=eth0   局域网里有 100.x 设备要主动访问本机时填写,放行 ts-input 丢包
CONF=/etc/default/ts-policy-routing
LAN_IFACE=""
[ -f "$CONF" ] && . "$CONF"

del_prio() { while ip -4 rule del priority "$1" 2>/dev/null; do :; done; }

fw_allow() {
  [ -n "$LAN_IFACE" ] || return 0
  command -v iptables >/dev/null || return 0
  iptables -nL ts-input >/dev/null 2>&1 || { echo "未找到 ts-input 链,跳过防火墙放行"; return 0; }
  # 先放行 LAN 来的 100.x,再在其上方丢弃伪造的 tailnet 源地址
  iptables -C ts-input -i "$LAN_IFACE" -s 100.0.0.0/8 -j ACCEPT 2>/dev/null \
    || iptables -I ts-input 1 -i "$LAN_IFACE" -s 100.0.0.0/8 -j ACCEPT
  iptables -C ts-input -i "$LAN_IFACE" -s 100.81.1.0/24 -j DROP 2>/dev/null \
    || iptables -I ts-input 1 -i "$LAN_IFACE" -s 100.81.1.0/24 -j DROP
}

start() {
  local r p sel t
  for r in "${RULES[@]}"; do
    IFS='|' read -r p sel t <<<"$r"
    del_prio "$p"
    ip -4 rule add priority "$p" to "$sel" lookup "$t"
  done
  fw_allow
}

stop() {
  local r p
  for r in "${RULES[@]}"; do
    IFS='|' read -r p _ _ <<<"$r"
    del_prio "$p"
  done
}

case "${1:-}" in
  start)  start ;;
  stop)   stop ;;
  status) ip -4 rule ;;
  *) echo "用法: $0 start|stop|status"; exit 1 ;;
esac
