#!/usr/bin/env bash
# 用法: sudo ./install.sh [--with-mihomo]
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "请用 sudo 运行"; exit 1; }
DIR=$(cd "$(dirname "$0")" && pwd)

# 1) 策略路由脚本 + systemd 服务
install -m 0755 "$DIR/ts-policy-routing.sh" /usr/local/sbin/ts-policy-routing.sh
install -m 0644 "$DIR/ts-policy-routing.service" /etc/systemd/system/ts-policy-routing.service
[ -f /etc/default/ts-policy-routing ] || printf '# 局域网里有 100.x 设备要主动访问本机时,取消注释并改成你的网卡名\n#LAN_IFACE=eth0\n' > /etc/default/ts-policy-routing

# 2) 使用 systemd-networkd 时,防止它清掉外部添加的策略路由
if systemctl is-active --quiet systemd-networkd; then
  install -D -m 0644 "$DIR/10-foreign.conf" /etc/systemd/networkd.conf.d/10-foreign.conf
  systemctl restart systemd-networkd
fi

systemctl daemon-reload
systemctl enable --now ts-policy-routing.service

# 3) 可选: 安装 mihomo 配置和服务(不会覆盖已有配置,也不会自动启动)
if [ "${1:-}" = "--with-mihomo" ]; then
  install -d /etc/mihomo
  [ -f /etc/mihomo/config.yaml ] || install -m 0600 "$DIR/mihomo-config.yaml" /etc/mihomo/config.yaml
  install -m 0644 "$DIR/mihomo.service" /etc/systemd/system/mihomo.service
  systemctl daemon-reload
  echo "已安装 mihomo 配置和服务。请先编辑 /etc/mihomo/config.yaml 里的 TODO 项,"
  echo "确认 /usr/local/bin/mihomo 存在后执行: sudo systemctl enable --now mihomo"
fi

echo "完成。运行 ./verify.sh 检查路由。"
