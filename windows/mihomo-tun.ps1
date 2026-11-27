# mihomo-tun (Windows 11): 在 Tailscale 网络下用 mihomo TUN 做全局代理
#
#   - tailnet 网段 / MagicDNS 走 Tailscale
#   - 其余 100.x 与私有网段走本地网络,不进 TUN
#   - 公网流量进 mihomo TUN(wintun),按规则分流;代理节点经 Tailscale 网卡访问
#
# 与 macOS 版思路相同: Windows 没有策略路由,用"更长前缀"的路由覆盖 Tailscale 的 100.64.0.0/10。
# 配置文件格式与 Linux / macOS 版相同(mihomo-tun.conf + proxies.yaml)。
#
# 需在管理员 PowerShell 中运行;兼容 Windows PowerShell 5.1(Win11 自带)。
# 本文件需保存为 UTF-8 with BOM,否则 5.1 会按 ANSI 读取中文。
#
# 用法: mihomo-tun help

#Requires -Version 5.1
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 1   # 只禁止未初始化变量;Version 2 会让访问 JSON 中缺失的字段报错

$VERSION = '0.1.0'

# ---------------------------------------------------------------- 路径与常量
$ConfDir     = if ($env:MIHOMO_TUN_CONF_DIR) { $env:MIHOMO_TUN_CONF_DIR } else { Join-Path $env:ProgramData 'mihomo-tun' }
$ConfFile    = Join-Path $ConfDir 'mihomo-tun.conf'
$ProxiesFile = Join-Path $ConfDir 'proxies.yaml'
$StateDir    = Join-Path $ConfDir 'state'
$RouteState  = Join-Path $StateDir 'routes'
$InstallDir  = Join-Path $env:ProgramFiles 'mihomo-tun'
$BinPath     = Join-Path $InstallDir 'mihomo-tun.ps1'
$SelfPath    = $MyInvocation.MyCommand.Path

# 计划任务(代替 systemd / launchd)
$TaskFolder   = '\mihomo-tun\'
$RoutesTask   = 'routes'      # 开机、网络变化、每分钟: routes-up(幂等)
$MihomoTask   = 'mihomo'      # 开机: run(循环运行 mihomo,退出后自动拉起)
$RollbackTask = 'rollback'    # start --rollback N

$NrptComment      = 'mihomo-tun'            # 分流 DNS 的 NRPT 规则
$NrptMagicComment = 'mihomo-tun-magicdns'   # MagicDNS 的 NRPT 规则
$FirewallRule     = 'mihomo-tun'

# 生成的配置里固定使用的名字(与 bash 版一致)
$TS_DIRECT     = 'TAILSCALE'
$SYSTEM_POLICY = 'SYSTEM'
$PROVIDER      = 'nodes'

# ---------------------------------------------------------------- 工具函数
function Info([string]$m) { Write-Host "[mihomo-tun] $m" }
function Warn([string]$m) { Write-Host "[mihomo-tun] 警告: $m" -ForegroundColor Yellow }
function Die([string]$m)  { Write-Host "[mihomo-tun] 错误: $m" -ForegroundColor Red; exit 1 }

function Assert-Admin {
  $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
  if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Die '请在管理员 PowerShell 中运行' }
}

function Test-IPv4([string]$s) { $s -match '^(\d{1,3}\.){3}\d{1,3}$' }

function ConvertTo-IPInt([string]$ip) {
  $b = ([Net.IPAddress]::Parse($ip)).GetAddressBytes()
  [int64]$b[0] * 16777216 + [int64]$b[1] * 65536 + [int64]$b[2] * 256 + [int64]$b[3]
}

function Test-InCidr([string]$ip, [string]$cidr) {
  $net, $len = $cidr.Split('/')
  $len = if ($len) { [int]$len } else { 32 }
  # 注意: 0xFFFFFFFF 在 PowerShell 里是 Int32 的 -1,这里用十进制
  $m = if ($len -eq 0) { [int64]0 } else { ([int64]4294967295 -shl (32 - $len)) -band [int64]4294967295 }
  ((ConvertTo-IPInt $ip) -band $m) -eq ((ConvertTo-IPInt $net) -band $m)
}

function Write-Utf8NoBom([string]$path, [string]$text) {
  # Windows PowerShell 5.1 的 Set-Content -Encoding UTF8 会带 BOM
  [IO.File]::WriteAllText($path, $text, (New-Object Text.UTF8Encoding($false)))
}

function Split-List([string]$s) { @($s -split '\s+' | Where-Object { $_ }) }

# ---------------------------------------------------------------- 配置
# 读取 shell 语法的 mihomo-tun.conf(只支持 KEY=value / KEY="a b",不执行任何代码)
function Read-Conf {
  $c = [ordered]@{
    TS_IFACE = 'auto'; TAILNET_CIDRS = ''; MAGICDNS_IP = '100.100.100.100'
    MAGICDNS_LINK = 'auto'; MAGICDNS_SUFFIX = 'auto'
    LOCAL_CIDRS = '100.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16'
    MIHOMO_BIN = (Join-Path $InstallDir 'mihomo.exe'); MIHOMO_DIR = ''
    LOG_LEVEL = 'info'; MIXED_PORT = '7890'; ALLOW_LAN = 'false'
    EXTERNAL_CONTROLLER = ''; EXTERNAL_SECRET = ''
    TUN_DEVICE = 'auto'; TUN_STACK = 'mixed'; TUN_ADDRESS = ''; TUN_MTU = '1400'
    SPLIT_DNS = 'yes'; SPLIT_DNS_DOMAINS = ''; TUN_DNS = '198.18.0.2'
    DNS_LISTEN = '127.0.0.1:1053'; DNS_NAMESERVERS = 'auto'
    FAKE_IP_RANGE = '198.18.0.1/16'; FAKE_IP_FILTER = '+.ts.net +.lan +.local'
    PROXY_VIA_TAILSCALE = 'yes'; PROXY_GROUP = 'PROXY'; PROXY_GROUP_TYPE = 'select'
    HEALTH_CHECK_URL = 'https://www.gstatic.com/generate_204'; FINAL_POLICY = 'auto'
    VERIFY_PROXY_IP = ''; VERIFY_LAN_IP = '192.168.1.1'
  }
  if (Test-Path -LiteralPath $ConfFile) {
    foreach ($line in Get-Content -LiteralPath $ConfFile -Encoding UTF8) {
      if ($line -notmatch '^\s*([A-Z_][A-Z0-9_]*)=(.*)$') { continue }
      $k = $Matches[1]; $v = $Matches[2].Trim()
      if ($v -match '^"([^"]*)"') { $v = $Matches[1] }
      elseif ($v -match "^'([^']*)'") { $v = $Matches[1] }
      else { $v = ($v -replace '\s+#.*$', '').Trim() }
      $c[$k] = $v
    }
  }
  # 示例配置是 Linux / macOS 的路径,Windows 下忽略
  if ($c.MIHOMO_BIN -like '/*') { $c.MIHOMO_BIN = Join-Path $InstallDir 'mihomo.exe' }
  if ($c.MIHOMO_DIR -like '/*' -or -not $c.MIHOMO_DIR) { $c.MIHOMO_DIR = Join-Path $ConfDir 'mihomo' }
  if ($c.TUN_DEVICE -eq 'auto') { $c.TUN_DEVICE = 'mihomo-tun' }   # wintun 网卡名

  $script:TsPrefs = Get-TsPrefs
  $script:ExitNode = [bool]($script:TsPrefs -and $script:TsPrefs.ExitNodeID)
  # Windows 同 macOS:未命中规则的流量从本机物理网卡出网(auto-detect-interface),与 exit node 开关无关
  if ($c.FINAL_POLICY -eq 'auto') { $c.FINAL_POLICY = 'DIRECT' }
  $script:C = $c
}

function Assert-Conf {
  if (-not (Test-Path -LiteralPath $ConfFile)) { Die "未找到 $ConfFile,请先执行 mihomo-tun install" }
  if (-not $C.TAILNET_CIDRS) { Die "$ConfFile 中 TAILNET_CIDRS 未设置" }
  foreach ($x in (Split-List "$($C.TAILNET_CIDRS) $($C.LOCAL_CIDRS)")) {
    if (-not (Test-IPv4 $x.Split('/')[0])) { Die "无效网段: $x" }
  }
}

function Get-TailnetTargets {   # 走 Tailscale 的网段
  $l = Split-List $C.TAILNET_CIDRS
  if ($C.MAGICDNS_IP) { $l += "$($C.MAGICDNS_IP)/32" }
  $l
}

# ---------------------------------------------------------------- Tailscale
function Get-TsCli {
  $c = Get-Command tailscale.exe -ErrorAction SilentlyContinue
  if ($c) { return $c.Source }
  $p = Join-Path $env:ProgramFiles 'Tailscale\tailscale.exe'
  if (Test-Path $p) { return $p }
  $null
}

function Invoke-Ts {
  $cli = Get-TsCli
  if (-not $cli) { return $null }
  # 5.1 下 EAP=Stop 时原生命令写 stderr 会抛异常
  $ErrorActionPreference = 'Continue'
  & $cli @args 2>$null
}

function Get-TsPrefs {
  $j = Invoke-Ts debug prefs
  if (-not $j) { return $null }
  try { ($j -join "`n") | ConvertFrom-Json } catch { $null }
}

# 返回 Tailscale 的 NetAdapter 对象(Name 用于 mihomo 的 interface-name)
function Get-TsAdapter {
  if ($C.TS_IFACE -ne 'auto') { return Get-NetAdapter -Name $C.TS_IFACE -ErrorAction SilentlyContinue }
  $ip = @(Invoke-Ts ip -4) | Select-Object -First 1
  if ($ip) {
    $a = Get-NetIPAddress -IPAddress $ip -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($a) { return Get-NetAdapter -InterfaceIndex $a.InterfaceIndex -ErrorAction SilentlyContinue }
  }
  Get-NetAdapter -ErrorAction SilentlyContinue |
    Where-Object { $_.InterfaceDescription -like 'Tailscale*' -and $_.Status -eq 'Up' } | Select-Object -First 1
}

function Get-TunAdapter { Get-NetAdapter -Name $C.TUN_DEVICE -ErrorAction SilentlyContinue }

# ---------------------------------------------------------------- proxies.yaml 解析(同 bash 版的简化 YAML 处理)
function Get-YamlSection([string]$key) {
  if (-not (Test-Path -LiteralPath $ProxiesFile)) { return @() }
  $in = $false
  foreach ($l in Get-Content -LiteralPath $ProxiesFile -Encoding UTF8) {
    if ($l -match '^([A-Za-z0-9_.-]+)\s*:') { $in = ($Matches[1] -eq $key); continue }
    if ($in) { $l }
  }
}

function Get-YamlTopKeys {
  foreach ($l in Get-Content -LiteralPath $ProxiesFile -Encoding UTF8) {
    if ($l -match '^([A-Za-z0-9_.-]+)\s*:') { $Matches[1] }
  }
}

function Test-SectionNonEmpty([string]$key) {
  [bool](@(Get-YamlSection $key | Where-Object { $_ -notmatch '^\s*(#.*)?$' }).Count)
}

function Get-Rules {   # 规范成纯规则行
  foreach ($l in Get-YamlSection 'rules') {
    $l = $l -replace '\s#.*$', '' -replace '^\s*#.*$', '' -replace '^\s*-\s*', ''
    $l = $l.Trim()
    if ($l -match '^"(.*)"$' -or $l -match "^'(.*)'$") { $l = $Matches[1] }
    if ($l) { $l }
  }
}

# "类型,内容,SYSTEM[,参数]" -> "SUB-RULE,(类型,内容),SYSTEM"
function Expand-SystemRule([string]$r) {
  $r -replace "^(.*),$SYSTEM_POLICY(,[A-Za-z-]+)*$", "SUB-RULE,(`$1),$SYSTEM_POLICY"
}

function Get-ProxyNames {
  foreach ($l in Get-YamlSection 'proxies') {
    if ($l -match '^\s*#') { continue }
    if ($l -match '^\s*-?\s*\{?\s*name:\s*["'']?([^"'',}\s]+)') { $Matches[1] }
  }
}

# proxies.yaml 中自定义的代理组:去掉整行注释和空行,统一成 2 空格缩进的列表项
function Get-UserGroups {
  $ls = @(Get-YamlSection 'proxy-groups' | Where-Object { $_ -notmatch '^\s*(#.*)?$' })
  if (-not $ls.Count) { return @() }
  $min = ($ls | ForEach-Object { ($_ -replace '^(\s*).*', '$1').Length } | Measure-Object -Minimum).Minimum
  foreach ($l in $ls) { '  ' + $l.Substring($min) }
}

# 自定义代理组的名字(只看列表项第一层的 name)
function Get-GroupNames {
  foreach ($l in Get-UserGroups) {
    if ($l -match '^  -\s*\{?\s*name:\s*["'']?([^"'',}#]*)') { $Matches[1].TrimEnd() }
  }
}

# 检查自定义代理组:名字不能含空格,不能与内置策略、节点或彼此重名
function Assert-Groups {
  $names = @(Get-GroupNames)
  $reserved = @($C.PROXY_GROUP, $TS_DIRECT, $SYSTEM_POLICY, 'DIRECT', 'REJECT', 'REJECT-DROP', 'PASS', 'COMPATIBLE', 'GLOBAL')
  $nodes = @(Get-ProxyNames)
  foreach ($g in $names) {
    if ($g -match '\s') { Die "$ProxiesFile 中 proxy-groups 的组名不能含空格: $g" }
    if ($reserved -contains $g) { Die "$ProxiesFile 中的代理组 $g 与内置策略重名" }
    if ($nodes -contains $g) { Die "$ProxiesFile 中的代理组 $g 与节点重名(规则里写节点名时会冲突)" }
  }
  $dup = @($names | Group-Object | Where-Object { $_.Count -gt 1 } | ForEach-Object { $_.Name })
  if ($dup.Count) { Die "$ProxiesFile 中有重名的代理组: $($dup -join ' ')" }
}

$ServerRe = '(^|[{,\s])server:\s*["'']?([^"'',}\s]+)'

# proxies.yaml 中各节点的 server(按出现顺序;跳过注释)
function Get-ProxyServers {
  foreach ($l in Get-YamlSection 'proxies') {
    if ($l -match '^\s*#') { continue }
    if ($l -match $ServerRe) { $Matches[2] }
  }
}

# server 是否在 tailnet 内: Tailscale 的 100.64.0.0/10、TAILNET_CIDRS 或 *.ts.net
function Test-TailnetServer([string]$h) {
  if ($h -match '\.ts\.net\.?$') { return $true }
  if (-not (Test-IPv4 $h)) { return $false }
  foreach ($c in @('100.64.0.0/10') + @(Split-List $C.TAILNET_CIDRS)) { if (Test-InCidr $h $c) { return $true } }
  $false
}

# 代理节点地址(verify 用):第一个 tailnet 节点的 server
function Get-FirstServer {
  foreach ($s in Get-ProxyServers) { if (Test-TailnetServer $s) { return $s } }
  ''
}

# provider 文件的 proxies 部分: PROXY_VIA_TAILSCALE=yes 时给 tailnet 内的节点加上 interface-name;
# 公网节点不绑定,由 auto-detect-interface 走物理网卡。节点里已写了 interface-name 的保持不变
function Get-ProviderProxies([string]$tsName) {
  $lines = @(Get-YamlSection 'proxies')
  $items = New-Object System.Collections.Generic.List[object]
  $cur = $null; $itemInd = -1
  foreach ($l in $lines) {
    if ($l -match '^(\s*)-' -and $l -notmatch '^\s*#') {
      $ind = $Matches[1].Length
      if ($itemInd -lt 0) { $itemInd = $ind }
      if ($ind -eq $itemInd) { $cur = New-Object System.Collections.Generic.List[string]; $items.Add($cur) }
    }
    if ($null -eq $cur) { $l; continue }   # 第一个节点之前的注释
    $cur.Add($l)
  }
  foreach ($it in $items) {
    $h = ''; $bind = $false; $manual = $false
    foreach ($l in $it) {
      if ($l -match '^\s*#') { continue }
      if ($l -match '(^|[{,\s])interface-name:') { $manual = $true; break }
      if (-not $h -and $l -match $ServerRe) { $h = $Matches[2] }
    }
    if (-not $manual -and $C.PROXY_VIA_TAILSCALE -eq 'yes' -and $h -and (Test-TailnetServer $h)) { $bind = $true }
    for ($i = 0; $i -lt $it.Count; $i++) {
      $l = $it[$i]
      if ($i -eq 0 -and $bind -and $l -match '^\s*-\s*\{') {
        ([regex]'\{').Replace($l, "{ interface-name: `"$tsName`",", 1); continue
      }
      $l
      if ($i -eq 0 -and $bind) {
        if ($l -match '^\s*-\s*$' -and $it.Count -gt 1) { $ind = ($it[1] -replace '^(\s*).*', '$1').Length }
        else { $ind = ($l -replace '^(\s*-\s*).*', '$1').Length }
        (' ' * $ind) + "interface-name: `"$tsName`"    # mihomo-tun: tailnet 节点绑定 Tailscale 网卡"
      }
    }
  }
}

# 找出被前面更宽的 DOMAIN-SUFFIX / 相同 DOMAIN 覆盖、永远匹配不到的规则
function Get-RuleLint {
  $seen = @()
  foreach ($r in Get-Rules) {
    $f = $r.Split(',')
    if ($f.Count -lt 2 -or ($f[0] -ne 'DOMAIN' -and $f[0] -ne 'DOMAIN-SUFFIX')) { continue }
    $d = $f[1].ToLower()
    foreach ($s in $seen) {
      $hit = ($d -eq $s.Key) -or ($s.Kind -eq 'DOMAIN-SUFFIX' -and $d.EndsWith(".$($s.Key)"))
      if ($hit -and -not ($s.Kind -eq 'DOMAIN' -and $f[0] -eq 'DOMAIN-SUFFIX')) {
        "规则 `"$r`" 被前面的 `"$($s.Line)`" 覆盖,永远匹配不到(需要时把它挪到前面)"; break
      }
    }
    $seen += [pscustomobject]@{ Key = $d; Kind = $f[0]; Line = $r }
  }
}

function Get-SplitDnsDomains {
  if ($C.SPLIT_DNS_DOMAINS) { return Split-List $C.SPLIT_DNS_DOMAINS }
  @(Get-Rules | ForEach-Object {
      $f = $_.Split(',')
      if ($f.Count -ge 3 -and ($f[0] -eq 'DOMAIN' -or $f[0] -eq 'DOMAIN-SUFFIX') -and
          @('DIRECT', $TS_DIRECT, $SYSTEM_POLICY) -notcontains $f[2]) { $f[1].ToLower() }
    }) | Sort-Object -Unique
}

# mihomo 的上游 DNS。auto: 用系统当前的 DNS(排除 Tailscale / TUN / 回环 / fake-ip / MagicDNS)
function Get-DnsServers {
  if ($C.DNS_NAMESERVERS -ne 'auto') { return Split-List $C.DNS_NAMESERVERS }
  $ts = Get-TsAdapter
  $skip = @($C.TUN_DEVICE); if ($ts) { $skip += $ts.Name }
  $l = @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $skip -notcontains $_.InterfaceAlias -and $_.InterfaceAlias -notlike 'Loopback*' } |
    ForEach-Object { $_.ServerAddresses } |
    Where-Object { (Test-IPv4 $_) -and $_ -notlike '127.*' -and $_ -ne $C.MAGICDNS_IP -and -not (Test-InCidr $_ $C.FAKE_IP_RANGE) } |
    Select-Object -Unique)
  if ($l.Count) { $l } else { @('223.5.5.5', '119.29.29.29') }
}

# ---------------------------------------------------------------- 生成 mihomo 配置
function Format-YamlList([string]$indent, $items) { foreach ($x in $items) { "$indent- `"$x`"" } }

function New-MihomoYaml([string]$tsName) {
  $o = New-Object System.Collections.Generic.List[string]
  $add = { param($s) foreach ($x in @($s)) { if ($null -ne $x) { $o.Add([string]$x) } } }
  $dns = Get-DnsServers
  $bypass = @(Get-TailnetTargets) + @(Split-List $C.LOCAL_CIDRS)

  & $add @(
    "# 由 mihomo-tun 根据 $ConfDir 下的配置自动生成,请勿直接修改。"
    '# 修改配置后执行: mihomo-tun restart'
    "mixed-port: $($C.MIXED_PORT)"
    "allow-lan: $($C.ALLOW_LAN)"
    'mode: rule'
    "log-level: $($C.LOG_LEVEL)"
    'ipv6: false'
    'unified-delay: true'
    'profile:'
    '  store-selected: true'
    '  store-fake-ip: true')
  if ($C.EXTERNAL_CONTROLLER) {
    & $add "external-controller: $($C.EXTERNAL_CONTROLLER)"
    if ($C.EXTERNAL_SECRET) { & $add "secret: `"$($C.EXTERNAL_SECRET)`"" }
  }

  & $add @(''
    'tun:'
    '  enable: true'
    "  stack: $($C.TUN_STACK)"
    "  device: $($C.TUN_DEVICE)"
    "  mtu: $($C.TUN_MTU)"
    '  auto-route: true'
    '  auto-detect-interface: true'
    '  strict-route: false          # TODO(win): 实测 strict-route 对 Tailscale / NRPT 的影响'
    '  dns-hijack:'
    '    - any:53')
  if ($C.TUN_ADDRESS) { & $add '  inet4-address:'; & $add (Format-YamlList '    ' (Split-List $C.TUN_ADDRESS)) }
  & $add '  route-exclude-address:     # 这些网段不进 TUN'
  & $add (Format-YamlList '    ' $bypass)

  & $add @(''
    'dns:'
    '  enable: true'
    "  listen: $($C.DNS_LISTEN)"
    '  ipv6: false'
    '  enhanced-mode: fake-ip'
    "  fake-ip-range: $($C.FAKE_IP_RANGE)"
    '  fake-ip-filter:')
  & $add (Format-YamlList '    ' (Split-List $C.FAKE_IP_FILTER))
  & $add '  nameserver:';              & $add (Format-YamlList '    ' $dns)
  & $add '  proxy-server-nameserver:'; & $add (Format-YamlList '    ' $dns)
  if ($C.MAGICDNS_IP) {
    & $add '  nameserver-policy:'
    & $add "    `"+.ts.net`": `"$($C.MAGICDNS_IP)#$TS_DIRECT`""
  }

  & $add @(''
    'sniffer:'
    '  enable: true'
    '  parse-pure-ip: true'
    '  override-destination: false'
    '  sniff:'
    '    TLS:  { ports: [443, 8443] }'
    '    HTTP: { ports: [80, 8080-8880] }'
    '    QUIC: { ports: [443] }'
    ''
    'proxies:'
    "  - name: $TS_DIRECT"
    '    type: direct'
    "    interface-name: `"$tsName`""
    ''
    'proxy-providers:'
    "  ${PROVIDER}:"
    '    type: file'
    '    path: ./providers/proxies.yaml   # tailnet 节点已在文件里绑定 Tailscale 网卡(见 Get-ProviderProxies)')
  $hc = @('url-test', 'fallback', 'load-balance') -contains $C.PROXY_GROUP_TYPE
  if ($hc) { & $add @('    health-check:', '      enable: true', "      url: $($C.HEALTH_CHECK_URL)", '      interval: 300') }

  & $add @('', 'proxy-groups:', "  - name: $($C.PROXY_GROUP)", "    type: $($C.PROXY_GROUP_TYPE)", "    use: [$PROVIDER]")
  if ($hc) { & $add @("    url: $($C.HEALTH_CHECK_URL)", '    interval: 300') }
  $reserved = @($C.PROXY_GROUP, $TS_DIRECT, $SYSTEM_POLICY, 'DIRECT', 'REJECT', 'REJECT-DROP', 'PASS', 'COMPATIBLE')
  foreach ($n in Get-ProxyNames) {
    if ($reserved -contains $n) { continue }
    $re = $n -replace '([\]\[\\.^$*+?(){}|/])', '\$1'
    & $add @("  - name: $n", '    type: select', "    use: [$PROVIDER]", "    filter: `"^$re`$`"")
  }

  # 自定义代理组原样追加,可以引用节点名(上面的同名组)、PROXY、DIRECT、TAILSCALE,或用 use: [nodes] + filter
  $ug = @(Get-UserGroups)
  if ($ug.Count) { & $add "  # ---- $ProxiesFile 中的 proxy-groups"; & $add $ug }

  if (Test-SectionNonEmpty 'rule-providers') {
    & $add @('', 'rule-providers:'); & $add @(Get-YamlSection 'rule-providers')
  }

  & $add @('', 'sub-rules:', "  ${SYSTEM_POLICY}:")
  foreach ($c in Get-TailnetTargets)          { & $add "    - IP-CIDR,$c,$TS_DIRECT" }
  foreach ($c in Split-List $C.LOCAL_CIDRS)   { & $add "    - IP-CIDR,$c,DIRECT" }
  & $add "    - MATCH,$($C.FINAL_POLICY)"

  & $add @('', 'rules:', "  - DOMAIN-SUFFIX,ts.net,$TS_DIRECT")
  foreach ($c in Get-TailnetTargets)          { & $add "  - IP-CIDR,$c,$TS_DIRECT,no-resolve" }
  foreach ($c in Split-List $C.LOCAL_CIDRS)   { & $add "  - IP-CIDR,$c,DIRECT,no-resolve" }
  & $add "  # ---- $ProxiesFile 中的 rules"
  foreach ($r in Get-Rules)                   { & $add "  - $(Expand-SystemRule $r)" }
  & $add '  # ----'
  foreach ($c in Split-List $C.TAILNET_CIDRS) { & $add "  - IP-CIDR,$c,$TS_DIRECT" }
  foreach ($c in Split-List $C.LOCAL_CIDRS)   { & $add "  - IP-CIDR,$c,DIRECT" }
  & $add "  - MATCH,$($C.FINAL_POLICY)"
  ($o -join "`n") + "`n"
}

function Invoke-Render([switch]$NoTest) {
  Read-Conf; Assert-Conf
  if (-not (Test-Path -LiteralPath $ProxiesFile)) { Die "未找到 $ProxiesFile" }
  if (Select-String -LiteralPath $ProxiesFile -Pattern 'CHANGE_ME' -SimpleMatch -Quiet) { Die "$ProxiesFile 里还有 CHANGE_ME,请先填写代理节点" }
  $ts = Get-TsAdapter
  if (-not $ts) { Die '未找到 Tailscale 网卡,Tailscale 是否已连接?(也可在配置里设置 TS_IFACE)' }

  if ($C.PROXY_VIA_TAILSCALE -eq 'yes') {
    foreach ($s in Get-ProxyServers) {
      if (-not (Test-IPv4 $s) -and -not (Test-TailnetServer $s)) { Warn "代理节点 server 是域名($s),按公网节点处理(不绑定 Tailscale 网卡);tailnet 节点请写 tailnet IP" }
    }
  }
  foreach ($k in Get-YamlTopKeys) {
    if (@('proxies', 'proxy-groups', 'rules', 'rule-providers') -notcontains $k) { Warn "$ProxiesFile 中的顶层键 $k 会被忽略(只支持 proxies / proxy-groups / rules / rule-providers)" }
  }
  Assert-Groups
  if (-not (Test-SectionNonEmpty 'proxies')) { Die "$ProxiesFile 中没有 proxies 节点" }
  foreach ($w in Get-RuleLint) { Warn $w }

  $dir = $C.MIHOMO_DIR
  New-Item -ItemType Directory -Force -Path (Join-Path $dir 'providers'), $StateDir | Out-Null
  $prov = "proxies:`n" + ((@(Get-ProviderProxies $ts.Name)) -join "`n") + "`n"
  Write-Utf8NoBom (Join-Path $dir 'providers\proxies.yaml') $prov
  $tmp = Join-Path $dir '.config.yaml.tmp'
  Write-Utf8NoBom $tmp (New-MihomoYaml $ts.Name)
  Move-Item -Force -LiteralPath $tmp -Destination (Join-Path $dir 'config.yaml')
  Set-Content -LiteralPath (Join-Path $StateDir 'ts_iface') -Value $ts.Name
  Set-Content -LiteralPath (Join-Path $StateDir 'exit_node') -Value ([int]$ExitNode)

  if ($NoTest) { return }
  if (Test-Path -LiteralPath $C.MIHOMO_BIN) {
    $ErrorActionPreference = 'Continue'
    $out = & $C.MIHOMO_BIN -t -d $dir 2>&1
    $ErrorActionPreference = 'Stop'
    if ($LASTEXITCODE -ne 0) { $out | Write-Host; Die 'mihomo 配置校验失败' }
    Info "已生成并校验 $dir\config.yaml (Tailscale 网卡: $($ts.Name))"
  } else {
    Warn "未找到 $($C.MIHOMO_BIN),跳过校验(可执行: mihomo-tun fetch-mihomo)"
  }
}

# ---------------------------------------------------------------- 路由
# 默认网关(排除 Tailscale / TUN),按 路由 metric + 网卡 metric 取最优
function Get-DefaultGw {
  $skip = @()
  $ts = Get-TsAdapter;  if ($ts)  { $skip += $ts.ifIndex }
  $tun = Get-TunAdapter; if ($tun) { $skip += $tun.ifIndex }
  Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
    Where-Object { $_.NextHop -ne '0.0.0.0' -and $skip -notcontains $_.InterfaceIndex } |
    Sort-Object { $_.RouteMetric + (Get-NetIPInterface -InterfaceIndex $_.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).InterfaceMetric } |
    Select-Object -First 1
}

# LOCAL_CIDRS 里需要盖过 Tailscale /10 的部分(同 mac_local_cidrs)
function Get-LocalOverrideCidrs {
  foreach ($c in Split-List $C.LOCAL_CIDRS) {
    $net, $len = $c.Split('/'); $len = if ($len) { [int]$len } else { 32 }
    if ($len -le 10 -and (Test-InCidr '100.64.0.0' $c)) { '100.64.0.0/11'; '100.96.0.0/11' }
    elseif (Test-InCidr $net '100.64.0.0/10') { $c }
  }
}

function Read-RouteState {
  if (Test-Path -LiteralPath $RouteState) { @(Get-Content -LiteralPath $RouteState | Where-Object { $_ }) } else { @() }
}

# Set-OurRoute <网段> <ifIndex> <下一跳,on-link 用 0.0.0.0>
# 已经正确就不动;只删除自己之前加的路由,不碰 Tailscale / 系统的路由
function Set-OurRoute([string]$prefix, [int]$ifIndex, [string]$nextHop) {
  $key = "$prefix|$ifIndex|$nextHop"
  $state = Read-RouteState
  $cur = @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix $prefix -PolicyStore ActiveStore -ErrorAction SilentlyContinue)
  if ($cur | Where-Object { $_.InterfaceIndex -eq $ifIndex -and $_.NextHop -eq $nextHop }) {
    if ($state -notcontains $key) { Add-Content -LiteralPath $RouteState -Value $key }
    return
  }
  foreach ($r in $cur) {
    if ($state -contains "$prefix|$($r.InterfaceIndex)|$($r.NextHop)") {
      Remove-NetRoute -InputObject $r -Confirm:$false -ErrorAction SilentlyContinue
    }
  }
  try {
    New-NetRoute -AddressFamily IPv4 -DestinationPrefix $prefix -InterfaceIndex $ifIndex -NextHop $nextHop `
      -RouteMetric 1 -PolicyStore ActiveStore -ErrorAction Stop | Out-Null
    Add-Content -LiteralPath $RouteState -Value $key
    Info "路由 $prefix -> if$ifIndex $nextHop"
  } catch { Warn "设置路由失败: $prefix -> if$ifIndex $nextHop ($($_.Exception.Message))" }
}

function Invoke-RoutesUp {
  Read-Conf
  New-Item -ItemType Directory -Force -Path $StateDir | Out-Null
  $gw = Get-DefaultGw
  if ($gw) { foreach ($c in Get-LocalOverrideCidrs) { Set-OurRoute $c $gw.InterfaceIndex $gw.NextHop } }
  else { Warn '没有找到默认网关,跳过本地网段路由' }

  $ts = Get-TsAdapter
  if ($ts) {
    # TODO(win): Tailscale 重新配置时可能清掉它网卡上"不认识"的路由(winipcfg syncRoutes),
    #            靠本任务每分钟 + 网络变化时重加;实测间隔是否可接受
    foreach ($c in Get-TailnetTargets) { Set-OurRoute $c $ts.ifIndex '0.0.0.0' }
    # Tailscale 网卡名变了(重装 / 改名),mihomo 里绑定的 interface-name 要跟着更新
    $f = Join-Path $StateDir 'ts_iface'
    $old = Get-Content -LiteralPath $f -ErrorAction SilentlyContinue
    if ($old -and $old -ne $ts.Name) {
      if (Get-MihomoProcess) { Info "Tailscale 网卡 $old -> $($ts.Name),重启 mihomo"; Restart-MihomoProcess }
      else { Set-Content -LiteralPath $f -Value $ts.Name }
    }
  } else { Warn '未找到 Tailscale 网卡(Tailscale 未连接?),跳过 tailnet 路由' }

  Set-MagicDns
  # mihomo 没在运行(崩溃 / 被杀)时 NRPT 规则会让这些域名解析失败,这里兜底清理
  if (-not (Get-TunAdapter)) { Remove-SplitDns }
}

function Invoke-RoutesDown {
  foreach ($k in Read-RouteState) {
    $prefix, $idx, $nh = $k.Split('|')
    Remove-NetRoute -AddressFamily IPv4 -DestinationPrefix $prefix -InterfaceIndex $idx -NextHop $nh `
      -PolicyStore ActiveStore -Confirm:$false -ErrorAction SilentlyContinue
  }
  Remove-Item -LiteralPath $RouteState -Force -ErrorAction SilentlyContinue
  Get-DnsClientNrptRule -ErrorAction SilentlyContinue | Where-Object Comment -eq $NrptMagicComment |
    ForEach-Object { Remove-DnsClientNrptRule -Name $_.Name -Force }
}

# ---------------------------------------------------------------- DNS(NRPT,代替 /etc/resolver)
function Remove-SplitDns {
  $r = @(Get-DnsClientNrptRule -ErrorAction SilentlyContinue | Where-Object Comment -eq $NrptComment)
  if ($r.Count) { $r | ForEach-Object { Remove-DnsClientNrptRule -Name $_.Name -Force }; Clear-DnsClientCache }
}

function Invoke-DnsUp {
  Read-Conf
  if ($C.SPLIT_DNS -ne 'yes') { return }
  $doms = @(Get-SplitDnsDomains)
  if (-not $doms.Count) { return }
  Remove-SplitDns
  # ".d" 匹配子域名,"d" 匹配自身;与 macOS /etc/resolver 的行为一致
  $ns = @($doms | ForEach-Object { ".$_"; $_ })
  Add-DnsClientNrptRule -Namespace $ns -NameServers $C.TUN_DNS -Comment $NrptComment | Out-Null
  Clear-DnsClientCache
  Info "分流 DNS -> mihomo: $($doms -join ' ')"
  # TODO(win): 加入域且有 GPO 下发 NRPT 时,本地 NRPT 规则不生效,需要检测并提示
}

function Invoke-DnsDown { Remove-SplitDns }

# tailscale 没开 accept-dns 时,用 NRPT 把 *.ts.net 交给 MagicDNS
function Set-MagicDns {
  $cur = @(Get-DnsClientNrptRule -ErrorAction SilentlyContinue | Where-Object Comment -eq $NrptMagicComment)
  $clear = { $cur | ForEach-Object { Remove-DnsClientNrptRule -Name $_.Name -Force } }
  $corp = if ($TsPrefs) { [bool]$TsPrefs.CorpDNS } else { $false }
  if (-not $C.MAGICDNS_IP -or $C.MAGICDNS_LINK -eq 'no' -or ($C.MAGICDNS_LINK -eq 'auto' -and $corp)) {
    & $clear; return   # 开了 accept-dns 时 Tailscale 自己会配 NRPT
  }
  $ns = @('.ts.net')
  $suffix = $C.MAGICDNS_SUFFIX
  if ($suffix -eq 'auto') {
    $st = Invoke-Ts status --json
    if ($st) { try { $suffix = (($st -join "`n") | ConvertFrom-Json).MagicDNSSuffix } catch { $suffix = '' } }
  }
  if ($suffix -and $suffix -notlike '*.ts.net') { $ns += ".$suffix" }
  # 每分钟都会执行,已经一致就不动
  if ($cur.Count -eq 1 -and (@($cur[0].Namespace) -join ' ') -eq ($ns -join ' ') -and
      (@($cur[0].NameServers) -join ' ') -eq $C.MAGICDNS_IP) { return }
  & $clear
  Add-DnsClientNrptRule -Namespace $ns -NameServers $C.MAGICDNS_IP -Comment $NrptMagicComment | Out-Null
  # TODO(win): 节点短名(ping vm)需要把 suffix 加进 DNS 搜索后缀(Set-DnsClientGlobalSetting -SuffixSearchList)
}

# ---------------------------------------------------------------- mihomo 进程
function Get-MihomoProcess {
  Get-Process -Name ([IO.Path]::GetFileNameWithoutExtension($C.MIHOMO_BIN)) -ErrorAction SilentlyContinue |
    Where-Object { $_.Path -eq $C.MIHOMO_BIN }
}

# 杀掉 mihomo 进程;run 的循环会重新生成配置并拉起
function Restart-MihomoProcess { Get-MihomoProcess | Stop-Process -Force -ErrorAction SilentlyContinue }

# 供计划任务调用: 循环 "生成配置 -> 运行 mihomo -> 退出后重来"
function Invoke-Run {
  Read-Conf
  if (-not (Test-Path -LiteralPath $C.MIHOMO_BIN)) { Die "未找到 $($C.MIHOMO_BIN)" }
  while ($true) {
    # 开机时 Tailscale 可能比本任务晚连上
    for ($i = 0; $i -lt 30 -and -not (Get-TsAdapter); $i++) { Start-Sleep 2 }
    try { Invoke-Render -NoTest } catch { Warn "生成配置失败: $_"; Start-Sleep 10; continue }
    $log = Join-Path $StateDir 'mihomo.log'
    $p = Start-Process -FilePath $C.MIHOMO_BIN -ArgumentList @('-d', "`"$($C.MIHOMO_DIR)`"") -NoNewWindow -PassThru `
      -RedirectStandardOutput $log -RedirectStandardError "$log.err"
    for ($i = 0; $i -lt 30 -and -not (Get-TunAdapter) -and -not $p.HasExited; $i++) { Start-Sleep -Milliseconds 500 }
    if (Get-TunAdapter) { Invoke-DnsUp } else { Warn "TUN 网卡 $($C.TUN_DEVICE) 未出现,跳过分流 DNS(见 $log)" }
    $p.WaitForExit()
    Remove-SplitDns
    Warn "mihomo 已退出(code $($p.ExitCode)),3 秒后重启"
    Start-Sleep 3
  }
}

# ---------------------------------------------------------------- 计划任务(代替 systemd / launchd)
function Get-TaskAction([string]$sub) {
  $log = Join-Path $StateDir "task-$sub.log"   # TODO(win): 日志轮转
  New-ScheduledTaskAction -Execute 'powershell.exe' -Argument (
    "-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command `"& '$BinPath' $sub *>> '$log'`"")
}

function Register-Tasks {
  $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
  $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero)

  # routes: 开机 + 每分钟 + 网络变化(NetworkProfile 10000 = 连上网络)
  $evCls = Get-CimClass -ClassName MSFT_TaskEventTrigger -Namespace Root/Microsoft/Windows/TaskScheduler
  $ev = New-CimInstance -CimClass $evCls -ClientOnly
  $ev.Enabled = $true
  $ev.Subscription = '<QueryList><Query Id="0" Path="Microsoft-Windows-NetworkProfile/Operational">' +
    '<Select Path="Microsoft-Windows-NetworkProfile/Operational">*[System[(EventID=10000 or EventID=10001)]]</Select></Query></QueryList>'
  $every = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 1)
  $boot = New-ScheduledTaskTrigger -AtStartup
  Register-ScheduledTask -TaskPath $TaskFolder -TaskName $RoutesTask -Action (Get-TaskAction 'routes-up') `
    -Trigger @($boot, $every, $ev) -Principal $principal -Settings $settings -Force | Out-Null

  # mihomo: 开机启动,run 内部循环保活
  Register-ScheduledTask -TaskPath $TaskFolder -TaskName $MihomoTask -Action (Get-TaskAction 'run') `
    -Trigger (New-ScheduledTaskTrigger -AtStartup) -Principal $principal -Settings $settings -Force | Out-Null
}

function Get-Parts([string]$p) {
  switch ($p) { '' { @('routes', 'mihomo') } 'routes' { @('routes') } 'mihomo' { @('mihomo') } default { Die "未知部分: $p(routes|mihomo)" } }
}

function Start-Part([string]$p) {
  $n = if ($p -eq 'routes') { $RoutesTask } else { $MihomoTask }
  Enable-ScheduledTask -TaskPath $TaskFolder -TaskName $n | Out-Null
  if ($p -eq 'routes') { Invoke-RoutesUp } else { Start-ScheduledTask -TaskPath $TaskFolder -TaskName $n }
}

function Stop-Part([string]$p) {
  $n = if ($p -eq 'routes') { $RoutesTask } else { $MihomoTask }
  Stop-ScheduledTask -TaskPath $TaskFolder -TaskName $n -ErrorAction SilentlyContinue
  Disable-ScheduledTask -TaskPath $TaskFolder -TaskName $n -ErrorAction SilentlyContinue | Out-Null
  if ($p -eq 'mihomo') { Restart-MihomoProcess; Remove-SplitDns }   # 先停任务(循环)再杀进程,否则会被重新拉起
  else { Invoke-RoutesDown }
}

function Set-Rollback([string]$minutes) {
  if (-not $minutes) { return }
  Unregister-ScheduledTask -TaskPath $TaskFolder -TaskName $RollbackTask -Confirm:$false -ErrorAction SilentlyContinue
  $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
  $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
  Register-ScheduledTask -TaskPath $TaskFolder -TaskName $RollbackTask -Action (Get-TaskAction 'stop') -Principal $principal -Settings $settings `
    -Trigger (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes([int]$minutes)) | Out-Null
  Info "已设置 $minutes 分钟后自动回滚(mihomo-tun stop)。确认一切正常后执行: mihomo-tun confirm"
}

function Read-SvcArgs($a) {
  $r = @{ Part = ''; Rollback = '' }
  for ($i = 0; $i -lt $a.Count; $i++) {
    if ($a[$i] -eq '--rollback') {
      $i++; $r.Rollback = if ($i -lt $a.Count) { $a[$i] } else { '' }
      if ($r.Rollback -notmatch '^\d+$') { Die '--rollback 需要分钟数' }
    } else { $r.Part = $a[$i] }
  }
  $r
}

# ---------------------------------------------------------------- 命令
function Invoke-Install {
  Assert-Admin
  New-Item -ItemType Directory -Force -Path $InstallDir, $ConfDir, $StateDir | Out-Null
  if ($SelfPath -ne $BinPath) { Copy-Item -Force -LiteralPath $SelfPath -Destination $BinPath }
  # 命令行入口: mihomo-tun.cmd
  Set-Content -LiteralPath (Join-Path $InstallDir 'mihomo-tun.cmd') -Encoding ASCII -Value (
    "@powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"%~dp0mihomo-tun.ps1`" %*")
  $path = [Environment]::GetEnvironmentVariable('Path', 'Machine')
  if (($path -split ';') -notcontains $InstallDir) {
    [Environment]::SetEnvironmentVariable('Path', "$path;$InstallDir", 'Machine')
    Info "已把 $InstallDir 加入 PATH(新开终端后生效)"
  }

  $examples = Join-Path (Split-Path -Parent (Split-Path -Parent $SelfPath)) 'conf'
  foreach ($f in @('mihomo-tun.conf', 'proxies.yaml')) {
    $dst = Join-Path $ConfDir $f
    $src = Join-Path $examples "$f.example"
    if (Test-Path -LiteralPath $dst) { continue }
    if (Test-Path -LiteralPath $src) { Copy-Item -LiteralPath $src -Destination $dst; Info "已生成 $dst,请修改" }
    else { Warn "未找到示例 $src,请手动创建 $dst" }
  }
  # 配置里有节点密码: 只允许 SYSTEM / Administrators 访问
  icacls $ConfDir /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' /T | Out-Null

  Read-Conf
  # mixed / system 栈的 TCP 需要放行入站
  if (-not (Get-NetFirewallRule -DisplayName $FirewallRule -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -DisplayName $FirewallRule -Direction Inbound -Program $C.MIHOMO_BIN -Action Allow | Out-Null
  }
  # 防止开机时带着示例配置自启;重复 install 时保留原来的启用状态(Register -Force 会重置任务)
  $prev = Get-ScheduledTask -TaskPath $TaskFolder -TaskName $MihomoTask -ErrorAction SilentlyContinue
  $wasEnabled = $prev -and $prev.State -ne 'Disabled'
  Register-Tasks
  if (-not $wasEnabled) { Disable-ScheduledTask -TaskPath $TaskFolder -TaskName $MihomoTask | Out-Null }
  Start-Part 'routes'
  Info "安装完成。编辑 $ConfFile 和 $ProxiesFile 后执行: mihomo-tun start --rollback 10"
}

function Invoke-Uninstall($a) {
  Assert-Admin
  $purge = ($a -contains '--purge') -or ($a -contains '--all')
  $rmBin = ($a -contains '--remove-mihomo') -or ($a -contains '--all')
  Read-Conf
  foreach ($p in @('mihomo', 'routes')) { Stop-Part $p }
  foreach ($t in @($MihomoTask, $RoutesTask, $RollbackTask)) {
    Unregister-ScheduledTask -TaskPath $TaskFolder -TaskName $t -Confirm:$false -ErrorAction SilentlyContinue
  }
  Remove-NetFirewallRule -DisplayName $FirewallRule -ErrorAction SilentlyContinue
  if ($rmBin) { Remove-Item -Force -LiteralPath $C.MIHOMO_BIN -ErrorAction SilentlyContinue }
  if ($purge) {
    if (($a -contains '-y') -or (Read-Host "删除 $ConfDir(含节点密码)? [y/N]") -eq 'y') { Remove-Item -Recurse -Force -LiteralPath $ConfDir }
  }
  Remove-Item -Force -LiteralPath $BinPath, (Join-Path $InstallDir 'mihomo-tun.cmd') -ErrorAction SilentlyContinue
  if (-not (Get-ChildItem -LiteralPath $InstallDir -ErrorAction SilentlyContinue)) {
    Remove-Item -Force -LiteralPath $InstallDir -ErrorAction SilentlyContinue
    $path = ([Environment]::GetEnvironmentVariable('Path', 'Machine') -split ';' | Where-Object { $_ -and $_ -ne $InstallDir }) -join ';'
    [Environment]::SetEnvironmentVariable('Path', $path, 'Machine')
  }
  if (Get-TunAdapter) { Warn "TUN 网卡 $($C.TUN_DEVICE) 仍存在" }
  if (@(Get-DnsClientNrptRule | Where-Object { $_.Comment -like 'mihomo-tun*' }).Count) { Warn '仍有 mihomo-tun 的 NRPT 规则残留' }
  Info '卸载完成'
}

function Invoke-Start($a) {
  Assert-Admin
  $s = Read-SvcArgs $a
  Read-Conf; Assert-Conf
  Set-Rollback $s.Rollback
  foreach ($p in Get-Parts $s.Part) {
    if ($p -eq 'mihomo') { Invoke-Render }   # 先校验,配置错了不启动
    Start-Part $p
  }
}

function Invoke-Stop($a) {
  Assert-Admin
  Read-Conf
  $parts = Get-Parts ($a | Select-Object -First 1)
  foreach ($p in @('mihomo', 'routes')) { if ($parts -contains $p) { Stop-Part $p } }   # 先停 mihomo 再撤路由
}

function Invoke-Restart($a) {
  Assert-Admin
  $s = Read-SvcArgs $a
  Read-Conf; Assert-Conf
  Set-Rollback $s.Rollback
  foreach ($p in Get-Parts $s.Part) {
    if ($p -eq 'routes') { Invoke-RoutesDown; Invoke-RoutesUp }
    else {
      Invoke-Render
      Stop-Part 'mihomo'; Start-Part 'mihomo'
    }
  }
}

function Invoke-Confirm {
  Assert-Admin
  if (Get-ScheduledTask -TaskPath $TaskFolder -TaskName $RollbackTask -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskPath $TaskFolder -TaskName $RollbackTask -Confirm:$false
    Info '已取消自动回滚'
  } else { Info '没有待执行的自动回滚' }
}

function Invoke-Status {
  Read-Conf
  Write-Host '== 计划任务 =='
  Get-ScheduledTask -TaskPath $TaskFolder -ErrorAction SilentlyContinue | ForEach-Object {
    $i = $_ | Get-ScheduledTaskInfo
    '{0,-10} {1,-10} 上次运行 {2} (结果 0x{3:X})' -f $_.TaskName, $_.State, $i.LastRunTime, $i.LastTaskResult
  }
  Write-Host "mihomo 进程: $(if (Get-MihomoProcess) { '运行中' } else { '未运行' })"
  Write-Host "`n== 网卡 =="
  $ts = Get-TsAdapter
  Write-Host "Tailscale: $(if ($ts) { "$($ts.Name) (if$($ts.ifIndex))" } else { '未找到' })"
  $tun = Get-TunAdapter
  Write-Host "TUN:       $(if ($tun) { "$($tun.Name) (if$($tun.ifIndex))" } else { '不存在' })"
  Write-Host "`n== 路由(100.x / 默认) =="
  Get-NetRoute -AddressFamily IPv4 -PolicyStore ActiveStore |
    Where-Object { $_.DestinationPrefix -like '100.*' -or $_.DestinationPrefix -eq '0.0.0.0/0' } |
    Sort-Object DestinationPrefix | Format-Table DestinationPrefix, InterfaceAlias, NextHop, RouteMetric -AutoSize | Out-String | Write-Host
  Write-Host '== NRPT =='
  Get-DnsClientNrptRule | Where-Object { $_.Comment -like 'mihomo-tun*' } |
    Format-Table Namespace, NameServers, Comment -AutoSize | Out-String | Write-Host
}

function Get-RouteIface([string]$ip) {
  (Find-NetRoute -RemoteIPAddress $ip -ErrorAction SilentlyContinue | Select-Object -First 1).InterfaceAlias
}

function Invoke-Verify {
  Read-Conf
  $ts = Get-TsAdapter; $tsName = if ($ts) { $ts.Name } else { '?' }
  $tunUp = [bool](Get-TunAdapter)
  $script:fail = $false
  function Check([string]$ip, [string]$want, [string]$desc) {
    $got = Get-RouteIface $ip
    $ok = switch ($want) {
      'ts'  { $got -eq $tsName }
      'lan' { $got -and $got -ne $tsName -and $got -ne $C.TUN_DEVICE }
      'tun' { $got -eq $C.TUN_DEVICE }
    }
    if (-not $ok) { $script:fail = $true }
    '{0,-4} {1,-18} -> {2,-14} ({3})' -f $(if ($ok) { 'OK' } else { 'FAIL' }), $ip, $(if ($got) { $got } else { '?' }), $desc
  }

  Write-Host '== exit node =='
  Write-Host $(if ($ExitNode) { "在用 (FINAL_POLICY=$($C.FINAL_POLICY))" } else { "未用 (FINAL_POLICY=$($C.FINAL_POLICY))" })

  Write-Host "`n== 路由走向 (Tailscale: $tsName, TUN: $($C.TUN_DEVICE)) =="
  $proxy = if ($C.VERIFY_PROXY_IP) { $C.VERIFY_PROXY_IP } else { Get-FirstServer }
  if ($proxy -and (Test-IPv4 $proxy)) { Check $proxy 'ts' '代理节点' }
  foreach ($c in Split-List $C.TAILNET_CIDRS) { Check $c.Split('/')[0] 'ts' "tailnet $c" }
  if ($C.MAGICDNS_IP) { Check $C.MAGICDNS_IP 'ts' 'MagicDNS' }
  foreach ($probe in @('100.99.0.5', '10.1.2.3', '172.20.0.1', $C.VERIFY_LAN_IP)) {
    $inTail = @(Split-List $C.TAILNET_CIDRS | Where-Object { Test-InCidr $probe $_ }).Count
    $inLocal = @(Split-List $C.LOCAL_CIDRS | Where-Object { Test-InCidr $probe $_ }).Count
    if (-not $inTail -and $inLocal) { Check $probe 'lan' '本地网段' }
  }
  if ($tunUp) { Check '8.8.8.8' 'tun' '公网 -> mihomo TUN' } else { Write-Host '--   8.8.8.8            (mihomo TUN 未启动,跳过)' }

  $doms = @(Get-SplitDnsDomains)
  if ($tunUp -and $C.SPLIT_DNS -eq 'yes' -and $doms.Count) {
    Write-Host "`n== 分流 DNS (应解析为 fake-ip $($C.FAKE_IP_RANGE)) =="
    foreach ($d in $doms) {
      $got = (Resolve-DnsName -Name $d -Type A -DnsOnly -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress } | Select-Object -First 1).IPAddress
      $ok = $got -and (Test-InCidr $got $C.FAKE_IP_RANGE)
      if (-not $ok) { $script:fail = $true }
      '{0,-4} {1,-24} -> {2}' -f $(if ($ok) { 'OK' } else { 'FAIL' }), $d, $(if ($got) { $got } else { '解析失败' })
    }
  }

  Write-Host "`n== Windows 特有检查 =="
  if (Get-NetRoute -AddressFamily IPv6 -DestinationPrefix '::/0' -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceAlias -ne $C.TUN_DEVICE }) {
    Write-Host 'WARN 存在 IPv6 默认路由: 本方案只处理 IPv4,IPv6 流量会绕过 TUN(可在物理网卡上关闭 IPv6)'
  }
  $smart = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Name DisableSmartNameResolution -ErrorAction SilentlyContinue
  if (-not $smart -or $smart.DisableSmartNameResolution -ne 1) {
    Write-Host 'WARN 未关闭 Smart Multi-Homed Name Resolution: 非 NRPT 域名的 DNS 查询会并发发往所有网卡'
  }
  # TODO(win): 检查 GPO 下发的 NRPT(HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig)

  if ($tunUp) {
    Write-Host "`n== 代理连通性 (经 mixed-port $($C.MIXED_PORT)) =="
    try {
      $r = Invoke-WebRequest -UseBasicParsing -TimeoutSec 8 -Proxy "http://127.0.0.1:$($C.MIXED_PORT)" -Uri $C.HEALTH_CHECK_URL
      Write-Host "$($C.HEALTH_CHECK_URL) -> HTTP $($r.StatusCode)"
    } catch { Write-Host "$($C.HEALTH_CHECK_URL) -> 失败: $($_.Exception.Message)" }
  }
  if ($script:fail) { exit 1 }
}

# 查询 GitHub release,返回 @{ Version; Url }
function Get-MihomoRelease([string]$ver) {
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  $arch = switch ($env:PROCESSOR_ARCHITECTURE) { 'AMD64' { 'amd64' } 'ARM64' { 'arm64' } default { Die "不支持的架构: $env:PROCESSOR_ARCHITECTURE" } }
  $api = if ($ver) { "https://api.github.com/repos/MetaCubeX/mihomo/releases/tags/$ver" } else { 'https://api.github.com/repos/MetaCubeX/mihomo/releases/latest' }
  $rel = Invoke-RestMethod -UseBasicParsing -Uri $api
  foreach ($n in @("mihomo-windows-$arch-$($rel.tag_name).zip", "mihomo-windows-$arch-compatible-$($rel.tag_name).zip", "mihomo-windows-$arch-v1-$($rel.tag_name).zip")) {
    $asset = $rel.assets | Where-Object name -eq $n | Select-Object -First 1
    if ($asset) { return @{ Version = $rel.tag_name; Url = $asset.browser_download_url } }
  }
  Die "在 $($rel.tag_name) 中没找到 windows-$arch 的二进制"
}

# 下载 zip 并把其中的 exe 保存为 $dest
function Save-MihomoExe([string]$url, [string]$dest) {
  $tmp = Join-Path $env:TEMP "mihomo-tun-$([guid]::NewGuid())"
  New-Item -ItemType Directory -Path $tmp | Out-Null
  try {
    Info "下载 $url"
    Invoke-WebRequest -UseBasicParsing -Uri ("$env:MIHOMO_DOWNLOAD_PREFIX" + $url) -OutFile (Join-Path $tmp 'm.zip')
    Expand-Archive -LiteralPath (Join-Path $tmp 'm.zip') -DestinationPath $tmp
    $exe = Get-ChildItem -LiteralPath $tmp -Filter '*.exe' -Recurse | Select-Object -First 1
    if (-not $exe) { Die '压缩包里没有 exe' }
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $dest) | Out-Null
    Copy-Item -Force -LiteralPath $exe.FullName -Destination $dest
  } finally { Remove-Item -Recurse -Force -LiteralPath $tmp -ErrorAction SilentlyContinue }
}

function Get-MihomoVersion([string]$exe) {
  if (-not (Test-Path -LiteralPath $exe)) { return '' }
  $ErrorActionPreference = 'Continue'
  $v = (& $exe -v 2>$null) -join ' '
  if ($v -match '(v\d+\.\d+\.\d+\S*)') { $Matches[1] } else { '' }
}

function Invoke-FetchMihomo($a) {
  Assert-Admin
  Read-Conf
  $rel = Get-MihomoRelease ($a | Select-Object -First 1)
  $running = @(Get-MihomoProcess)
  if ($running.Count) { $running | Stop-Process -Force; Start-Sleep 1 }   # 运行中的 exe 无法覆盖;run 循环会重新拉起
  Save-MihomoExe $rel.Url $C.MIHOMO_BIN
  & $C.MIHOMO_BIN -v
  # TODO(win): 确认 mihomo 内置 wintun;若创建 TUN 失败,把 wintun.dll 放到 mihomo.exe 同目录
}

# update [版本] [--force]: 新版本校验当前配置通过后才替换;
# 运行中的 mihomo 会重启,重启后 TUN 没起来则自动换回旧版本
function Invoke-Update($a) {
  Assert-Admin
  Read-Conf
  $want = ''; $force = $false
  foreach ($x in $a) {
    if ($x -eq '--force' -or $x -eq '-f') { $force = $true }
    elseif ($x -like '-*') { Die "未知参数: $x" }
    else { $want = $x }
  }
  $bin = $C.MIHOMO_BIN
  if (-not (Test-Path -LiteralPath $bin)) { Die "未找到 $bin,请先执行: mihomo-tun fetch-mihomo" }
  $cur = Get-MihomoVersion $bin
  $rel = Get-MihomoRelease $want
  if ($cur -eq $rel.Version -and -not $force) { Info "mihomo 已是 $cur,无需升级(强制重装加 --force)"; return }
  Info "mihomo $(if ($cur) { $cur } else { '未知版本' }) -> $($rel.Version)"

  $new = "$bin.new"; $bak = "$bin.bak"
  Save-MihomoExe $rel.Url $new
  if (-not (Get-MihomoVersion $new)) { Remove-Item -Force $new; Die '新版本无法运行' }
  if (Test-Path -LiteralPath (Join-Path $C.MIHOMO_DIR 'config.yaml')) {
    $ErrorActionPreference = 'Continue'
    $out = & $new -t -d $C.MIHOMO_DIR 2>&1
    $ErrorActionPreference = 'Stop'
    if ($LASTEXITCODE -ne 0) { $out | Write-Host; Remove-Item -Force $new; Die '新版本校验当前配置失败,未替换' }
  }

  # 运行中的 exe 不能覆盖,但可以改名: 旧文件改成 .bak,新文件放到原路径
  $running = @(Get-MihomoProcess)   # 改名前先拿到进程对象,改名后 Path 可能变化
  Remove-Item -Force -LiteralPath $bak -ErrorAction SilentlyContinue
  Move-Item -LiteralPath $bin -Destination $bak
  Move-Item -LiteralPath $new -Destination $bin

  if ($running.Count) {
    # 杀掉旧进程后,run 循环会用新的 exe 重新拉起
    Info '重启 mihomo'
    $running | Stop-Process -Force
    Start-Sleep 2
    $ok = $false
    for ($i = 0; $i -lt 30; $i++) {
      if ((Get-MihomoProcess) -and (Get-TunAdapter)) { $ok = $true; break }
      Start-Sleep -Milliseconds 500
    }
    if (-not $ok) {
      Warn "新版本启动后 TUN 网卡 $($C.TUN_DEVICE) 没有出现,换回 $cur"
      # 新 exe 可能正被 run 循环拉起占用: 同样先改名再放回旧版本,然后杀掉新进程
      Remove-Item -Force -LiteralPath "$bin.failed" -ErrorAction SilentlyContinue
      Move-Item -LiteralPath $bin -Destination "$bin.failed"
      Move-Item -LiteralPath $bak -Destination $bin
      Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path -like "$bin*" } | Stop-Process -Force -ErrorAction SilentlyContinue
      Die "升级失败,已回滚(日志: $StateDir\mihomo.log)"
    }
  }
  Info "已升级到 $(Get-MihomoVersion $bin)(旧版本备份在 $bak)"
}

function Show-Usage {
  @"
mihomo-tun $VERSION — Tailscale 网络下的 mihomo TUN 全局代理 (Windows)

用法(管理员终端): mihomo-tun <命令> [参数]

  install                 安装脚本、示例配置、计划任务(可重复执行,不覆盖已有配置)
  uninstall [选项]        停止并删除计划任务、路由、NRPT、脚本(默认保留配置和 mihomo)
                            --purge / --remove-mihomo / --all / -y
  start   [routes|mihomo] [--rollback 分钟]   启动并设为开机自启(默认两者)
  stop    [routes|mihomo]                   停止并取消开机自启
  restart [routes|mihomo] [--rollback 分钟]   重新生成配置并重启
  confirm                 确认正常,取消自动回滚
  status                  计划任务、网卡、路由、NRPT
  verify                  检查各网段的实际路由走向与分流 DNS
  render                  只生成并校验 mihomo 配置
  routes-up | routes-down 手动添加 / 删除路由
  dns-up | dns-down       手动设置 / 撤销分流 DNS(NRPT)
  fetch-mihomo [版本]     从 GitHub 下载 mihomo 到 MIHOMO_BIN(默认最新版)
  update [版本] [--force] 升级 mihomo 并重启;校验配置失败或启动失败时保留 / 换回旧版本
  run                     (供计划任务调用)循环运行 mihomo

配置目录: $ConfDir  (可用环境变量 MIHOMO_TUN_CONF_DIR 覆盖)
"@ | Write-Host
}

# ---------------------------------------------------------------- 入口
$cmd = if ($args.Count) { $args[0] } else { 'help' }
$rest = @($args | Select-Object -Skip 1)
switch ($cmd) {
  'install'      { Invoke-Install }
  'uninstall'    { Invoke-Uninstall $rest }
  'start'        { Invoke-Start $rest }
  'stop'         { Invoke-Stop $rest }
  'restart'      { Invoke-Restart $rest }
  'confirm'      { Invoke-Confirm }
  'status'       { Invoke-Status }
  'verify'       { Invoke-Verify }
  'render'       { Assert-Admin; Invoke-Render }
  'run'          { Invoke-Run }
  'routes-up'    { Assert-Admin; Invoke-RoutesUp }
  'routes-down'  { Assert-Admin; Read-Conf; Invoke-RoutesDown }
  'dns-up'       { Assert-Admin; Invoke-DnsUp }
  'dns-down'     { Assert-Admin; Read-Conf; Invoke-DnsDown }
  'fetch-mihomo' { Invoke-FetchMihomo $rest }
  'update'       { Invoke-Update $rest }
  { $_ -in 'version', '-v', '--version' } { "mihomo-tun $VERSION" }
  { $_ -in 'help', '-h', '--help' } { Show-Usage }
  default        { Show-Usage; exit 1 }
}
