#!/usr/bin/env bash
# 验证路由走向。用法: ./verify.sh [代理节点tailnet IP] [局域网设备IP]
PROXY_IP=${1:-100.81.1.10}
LAN_IP=${2:-192.168.1.1}
TUN=mihomo-tun

dev_of() { ip -4 route get "$1" 2>/dev/null | grep -o 'dev [^ ]*' | head -1 | awk '{print $2}'; }

check() {  # check <IP> <ts|lan|tun> <说明>
  local got ok=0; got=$(dev_of "$1")
  case "$2" in
    ts)  [ "$got" = tailscale0 ] && ok=1 ;;
    lan) [ -n "$got" ] && [ "$got" != tailscale0 ] && [ "$got" != "$TUN" ] && ok=1 ;;
    tun) [ "$got" = "$TUN" ] && ok=1 ;;
  esac
  printf '%-4s %-18s -> %-12s (%s)\n' "$([ $ok = 1 ] && echo OK || echo FAIL)" "$1" "${got:-?}" "$3"
}

echo "== 策略路由 =="
ip -4 rule | grep -E '^(519[01]|520[0-3]|52[1-7]0):' || echo "未找到预期规则"
echo
echo "== 路由走向 =="
check "$PROXY_IP"        ts  "代理节点/tailnet"
check 100.100.100.100    ts  "MagicDNS"
check 100.99.0.5         lan "其他 100.x"
check 10.1.2.3           lan "10.0.0.0/8"
check 172.20.0.1         lan "172.16.0.0/12"
check "$LAN_IP"          lan "192.168.0.0/16"
check 8.8.8.8            tun "公网(mihomo 已启动且未开 exit node 时)"
echo
echo "== 代理流量是否误走物理网卡(访问被代理网站时,应无输出) =="
echo "sudo tcpdump -ni <物理网卡> host $PROXY_IP"
