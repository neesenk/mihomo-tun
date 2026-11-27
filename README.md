# mihomo-tun

在 Tailscale 网络下,用 mihomo TUN 做全局代理。支持 Linux(systemd)和 macOS(launchd)。

## 解决的问题

本地网络也在用 `100.x` / 私有网段,而 Tailscale 默认接管整个 `100.64.0.0/10`,并且代理节点只能经 tailnet 访问:

| 目的地 | 走向 |
|---|---|
| `TAILNET_CIDRS`、MagicDNS `100.100.100.100` | Tailscale |
| `LOCAL_CIDRS`(其余 100.x、10/8、172.16/12、192.168/16) | 本地网络,不进 TUN |
| 公网 | mihomo TUN → 按 `proxies.yaml` 中的 `rules` 分流;代理节点经 Tailscale 网卡连接 |

## 快速开始

```bash
sudo ./mihomo-tun install          # 安装到 /usr/local/bin,生成示例配置,启动路由服务
sudo vi /etc/mihomo-tun/mihomo-tun.conf   # macOS: /usr/local/etc/mihomo-tun/
sudo vi /etc/mihomo-tun/proxies.yaml
sudo mihomo-tun fetch-mihomo       # 没有 mihomo 时
sudo mihomo-tun update             # 升级 mihomo(可指定版本,--force 强制重装),失败自动换回旧版本
sudo mihomo-tun start --rollback 10   # 远程机器上建议加:10 分钟后自动 stop,防止改坏网络后失联
sudo mihomo-tun verify
sudo mihomo-tun confirm               # 确认正常后取消自动回滚
```

改了配置之后执行 `sudo mihomo-tun restart`。`install` 可以重复执行,不会覆盖已有的配置文件。

## 卸载

```bash
sudo mihomo-tun uninstall                 # 停服务、删路由规则/服务定义/脚本,保留配置和 mihomo
sudo mihomo-tun uninstall --purge         # 同时删除配置目录(会二次确认,含节点密码)
sudo mihomo-tun uninstall --all -y        # 连 mihomo 二进制一起删,不确认
```

卸载结束会检查策略路由和 TUN 设备有没有残留。删除 networkd 的配置文件后不会立即重启 systemd-networkd,
以免它清掉 Tailscale 当前的策略路由;下次重启时自然恢复默认行为。

## 配置文件

| 文件 | 内容 |
|---|---|
| `mihomo-tun.conf` | 网络参数(tailnet 网段、本地网段、端口、DNS、TUN 等),shell 语法 |
| `proxies.yaml` | `proxies`(代理节点,写法同 mihomo,**不用写 `interface-name`**)、`rules`(分流规则,策略可用 `PROXY` / `DIRECT` / `REJECT` / `TAILSCALE` / `SYSTEM`,示例里有各类规则的写法)、可选的 `rule-providers`(供 `RULE-SET` 使用) |

mihomo 的 `config.yaml` 在启动时由脚本生成(`<配置目录>/mihomo/config.yaml`),不要手动修改它。

## 实现

**Linux**:`ip rule` 策略路由,优先级 5190–5209,排在 Tailscale 的 5210–5270 前面。
- tailnet → `lookup 52`(Tailscale 的路由表);本地网段 → `lookup main`
- mihomo `auto-route` 的规则(9000+)排在更后面,所以本地网段不会进 TUN
- `PartOf=tailscaled.service`:tailscaled 重启时规则会一并重建
- 用了 systemd-networkd 时,会安装 `networkd.conf.d/10-mihomo-tun.conf`,防止策略路由被清掉

**macOS**:没有策略路由,改用"更长前缀"来覆盖:
- `100.64.0.0/11` + `100.96.0.0/11` → 物理网关(比 Tailscale 的 /10 更具体)
- `TAILNET_CIDRS`、`100.100.100.100/32` → Tailscale 的 `utunN`(比上面的 /11 更具体)
- launchd 任务在网络变化时和每 60 秒检查一次,网关或 utun 变了就修正;
  Tailscale 的 utun 编号变化时,会自动重启 mihomo 以更新绑定的网卡

**mihomo 侧**
- `auto-detect-interface` 会把出站 socket 绑定到物理网卡,所以代理节点要通过 provider 的
  `override.interface-name` 绑定到 Tailscale 网卡,MagicDNS 查询也要走绑定了该网卡的 `TAILSCALE` 出口
- 不开 `auto-redirect`,避免和 Tailscale 的 netfilter 规则冲突

## exit node

本机在用 Tailscale exit node 时,Tailscale 的路由表 52 里有默认路由,它的 5270 规则会抢在 mihomo 前面拿走全部公网流量。
`TUN_RULE_INDEX=auto` 和 `FINAL_POLICY=auto` 会自动处理:
- mihomo 的规则放到 5255,排在 5270 之前,公网流量会进 TUN
- 没有命中规则的流量走 `TAILSCALE` 出口,仍然经 exit node 出网

开关 exit node 之后要执行 `sudo mihomo-tun restart`,`verify` 会检查状态是否一致。

macOS / Windows 上 `FINAL_POLICY=auto` 总是 `DIRECT`:未命中规则的流量从本机物理网卡出网(`auto-detect-interface` 绑定物理网卡,
不经过 exit node),开关 exit node 不需要重启。需要 AI 等流量走 exit node / 节点时,在 rules 里显式写节点名或 `TAILSCALE`。

## 规则里写节点名

每个节点会自动生成一个同名的组,规则里可以直接写节点名,把某类流量固定发给某个节点:
```yaml
  - DOMAIN-SUFFIX,git.garena.com,macpro   # 只有办公网节点能访问
  - DOMAIN-SUFFIX,garena.com,PROXY
```
规则按从上到下的顺序匹配,更具体的要写在前面。生成配置时会检查被前面规则覆盖、永远匹配不到的规则,并给出警告。

## MagicDNS

tailscale 没开 accept-dns 时,系统解析不了 `*.ts.net` 和节点短名。`routes-up` 会在 systemd-resolved 的
tailscale0 上配置 `100.100.100.100` 和 `~ts.net <tailnet 后缀>`,之后可以 `ping vm`(`MAGICDNS_LINK=auto`)。
resolved 发查询时绑定 tailscale0,不受其他策略路由影响。

`/etc/resolv.conf` 不是 resolved stub 的机器上,不建议开 accept-dns。tailscale 会进入 direct 模式,直接改写
resolv.conf。

## 分流 DNS

`proxies.yaml` 的 rules 中 `DOMAIN` / `DOMAIN-SUFFIX`(策略不是 DIRECT/TAILSCALE)的域名,会经 systemd-resolved
交给 mihomo 解析成 fake-ip。这样即使它们在本机解析到被排除的内网地址,流量也会进 TUN,被转给代理节点。
不需要程序支持代理。

- 前提:程序要经过 resolved 解析。`/etc/resolv.conf` 不是 `127.0.0.53` 时,`install` 会询问是否安装 `libnss-resolve`
  (`--nss-resolve` 不询问直接装)。它会在 `/etc/nsswitch.conf` 中加入 `resolve`,原文件备份为 `/etc/nsswitch.conf.mihomo-tun.bak`。
  `uninstall` 会把这一项去掉。`verify` 会检查这一点。
- 不读 nsswitch 的程序(静态编译的 Go 程序)不生效。
- 其他公司域名 CNAME 到这些域名时也会被代理。不希望走代理的程序(如系统/公司 agent),在 rules 最前面加
  `PROCESS-NAME,<程序名>,SYSTEM` 或 `PROCESS-PATH-REGEX,^/opt/xxx/,SYSTEM`。
  `SYSTEM` 是内置策略(用 mihomo `sub-rules` 实现),效果和没有 mihomo 时一样:本地网段直连,tailnet 走 Tailscale,
  其余按 `FINAL_POLICY`。不要用 `DIRECT`,它会让公网流量绕过 exit node。
- mihomo 停止后 TUN 网卡消失,resolved 的分流配置随之失效,这些域名恢复正常解析。

## 已知限制

- 只处理 IPv4(`ipv6: false`),IPv6 流量不经过代理
- 系统 DNS 是被排除的内网地址时,DNS 不会被劫持,域名规则依赖 sniffer(SNI/Host)
- macOS:Tailscale 下发的子网路由(`--accept-routes`)如果比 `LOCAL_CIDRS` 更具体,仍然会走 Tailscale
  (Linux 下本地规则优先)
- macOS TUN 设备名默认是 `utun225`,和其他软件冲突时修改 `TUN_DEVICE`

## 从旧版迁移

旧脚本在 `legacy/` 里。`install` 会自动停用并删除 `ts-policy-routing.service`。旧的 `mihomo.service` 需要手动停用:
`sudo systemctl disable --now mihomo`。
旧版独立的 `rules.txt` 仍会被读取(带警告),建议把内容移到 `proxies.yaml` 的 `rules:` 下后删除。
旧的 `/etc/default/ts-policy-routing` 里的 `LAN_IFACE` 要手动搬到 `mihomo-tun.conf`。

## Windows 11(实验性)

`windows/mihomo-tun.ps1` 是 PowerShell 版骨架，配置文件格式相同，尚未在真机上验证（代码里标了 `TODO(win)`）。

```powershell
# 管理员 PowerShell
powershell -ExecutionPolicy Bypass -File .\windows\mihomo-tun.ps1 install
notepad C:\ProgramData\mihomo-tun\mihomo-tun.conf
notepad C:\ProgramData\mihomo-tun\proxies.yaml
mihomo-tun fetch-mihomo            # 以后升级: mihomo-tun update
mihomo-tun start --rollback 10
mihomo-tun verify
mihomo-tun confirm
```

与 macOS 版的对应关系：
- 路由：同样用"更长前缀"覆盖 Tailscale 的 `100.64.0.0/10`（`New-NetRoute -PolicyStore ActiveStore`，不持久化，开机由任务重建）
- 服务：计划任务 `\mihomo-tun\routes`（开机、网络变化、每分钟执行 `routes-up`）和 `\mihomo-tun\mihomo`（开机执行 `run`，循环运行 mihomo）
- 分流 DNS / MagicDNS：NRPT 规则（`Get-DnsClientNrptRule`，Comment 为 `mihomo-tun*`）。mihomo 退出时会删除；异常退出时由 routes 任务兜底清理
- TUN：mihomo 的 wintun 网卡，默认名 `mihomo-tun`
- exit node：`FINAL_POLICY=auto` 总是 `DIRECT`，未命中规则的流量从本机出网，开关 exit node 不需要重启

已知风险：Tailscale 重新配置时可能删掉它网卡上的 tailnet 路由（最多 1 分钟后由 routes 任务补回）；IPv6 和 Smart Multi-Homed Name Resolution 需要手动处理，`verify` 会提示。
