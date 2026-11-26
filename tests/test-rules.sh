#!/usr/bin/env bash
# 分流规则端到端测试:真实发起连接,再从 mihomo API 查它命中的规则和出口。
#
#   sudo tests/test-rules.sh            # 跑全部用例
#   sudo tests/test-rules.sh -v         # 同时打印每条连接的详情
#
# 进程规则:把 curl 复制成对应的名字/路径(如 .../.local/share/claude/versions/x、codex、agy)再去连接,
#           这样 mihomo 看到的进程名/路径和真实程序一致。
# 域名规则:用 openssl s_client 发 SNI(非分流 DNS 的域名靠 sniffer 识别)。
# /Applications 下的 app 无法伪造路径,只检查规则是否存在,以及当前正在运行的 app 连接走向。
#
# 用例表在下面 CASES_PROC / CASES_DOMAIN,按 proxies.yaml 的 rules 修改。
set -u

CONF_DIR=${MIHOMO_TUN_CONF_DIR:-/usr/local/etc/mihomo-tun}
[ "$(uname)" = Linux ] && CONF_DIR=${MIHOMO_TUN_CONF_DIR:-/etc/mihomo-tun}
VERBOSE=0; [ "${1:-}" = -v ] && VERBOSE=1
[ "$(id -u)" = 0 ] || { echo "请用 sudo 运行: sudo $0 $*" >&2; exit 2; }

# shellcheck disable=SC1091
. "$CONF_DIR/mihomo-tun.conf" || exit 2
API=http://${EXTERNAL_CONTROLLER:?mihomo-tun.conf 里没有 EXTERNAL_CONTROLLER}
AUTH="Authorization: Bearer ${EXTERNAL_SECRET:-}"
CFG=$CONF_DIR/mihomo/config.yaml

# 下载慢速大文件,保持连接打开,便于在 /connections 里看到
HOLD_URL=https://speed.cloudflare.com/__down?bytes=5000000

# 进程用例: 名称|相对测试目录的程序路径|期望出口
CASES_PROC=(
  "Claude Code CLI|.local/share/claude/versions/9.9.9|sg"
  "Codex CLI|bin/codex|sg"
  "agy CLI|bin/agy|sg"
  "Codex 运行时|.codex/bin/node|sg"
  "对照: 普通进程|bin/plain-curl|TAILSCALE"
)
# 域名用例: 域名|期望出口
CASES_DOMAIN=(
  "api.anthropic.com|sg"
  "claude.ai|sg"
  "api.openai.com|sg"
  "chatgpt.com|sg"
  "cdn.oaistatic.com|sg"
  "www.google.com|sg"
  "github.com|sg"
  "www.youtube.com|sg"
  "git.garena.com|macpro"
  "www.baidu.com|DIRECT"
  "speed.cloudflare.com|TAILSCALE"
)
# 只能静态检查的 app 规则: 进程路径前缀|期望出口
CASES_APP=(
  "/Applications/Claude.app/|sg"
  "/Applications/ChatGPT.app/|sg"
  "/Applications/Antigravity.app/|sg"
)

pass=0; fail=0; skip=0
ok()   { pass=$((pass + 1)); printf '\033[32mPASS\033[0m %s\n' "$*"; }
bad()  { fail=$((fail + 1)); printf '\033[31mFAIL\033[0m %s\n' "$*"; }
skp()  { skip=$((skip + 1)); printf '\033[33mSKIP\033[0m %s\n' "$*"; }

# mihomo 上报的是解析后的真实路径(macOS 上 /var -> /private/var)
W=$(cd "$(mktemp -d)" && pwd -P); SNAP=$W/conns.jsonl; : >"$SNAP"
PIDS=()
cleanup() { for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done; rm -rf "$W"; }
trap cleanup EXIT

curl -fsS -m 3 -H "$AUTH" "$API/version" >/dev/null || { echo "连不上 mihomo API $API,mihomo 是否在运行?" >&2; exit 2; }

# ---- 发起连接
for c in "${CASES_PROC[@]}"; do
  IFS='|' read -r _ rel _ <<<"$c"
  mkdir -p "$W/$(dirname "$rel")"; cp /usr/bin/curl "$W/$rel"
  # macOS 上复制出来的系统二进制签名失效会被直接 kill,需要重新 ad-hoc 签名
  [ "$(uname)" = Darwin ] && codesign --force -s - "$W/$rel" 2>/dev/null
  "$W/$rel" -s -o /dev/null -m 8 --limit-rate 20k "$HOLD_URL" &
  PIDS+=($!); disown $!
done
for c in "${CASES_DOMAIN[@]}"; do
  IFS='|' read -r host _ <<<"$c"
  ( sleep 6 | openssl s_client -connect "$host:443" -servername "$host" -quiet >/dev/null 2>&1 ) &
  PIDS+=($!); disown $!
done

# ---- 连接期间多次抓取 /connections(连接可能很快关闭)
for _ in 1 2 3 4 5 6; do
  sleep 0.7
  curl -fsS -m 3 -H "$AUTH" "$API/connections" >>"$SNAP" && echo >>"$SNAP"
done

# lookup <proc|host> <值>  →  输出 "规则,载荷|出口链"(取第一条)
lookup() {
  python3 -I - "$SNAP" "$1" "$2" <<'EOF'
import json, sys
snap, kind, val = sys.argv[1:]
for line in open(snap):
    line = line.strip()
    if not line:
        continue
    for c in json.loads(line).get("connections") or []:
        m = c["metadata"]
        if kind == "proc" and m.get("processPath") != val:
            continue
        # fake-ip 域名在 host 里;真实 IP 的连接由 sniffer 识别,域名在 sniffHost 里
        if kind == "host" and (val not in (m.get("host"), m.get("sniffHost")) or m.get("process") != "openssl"):
            continue
        # 用 tab 分隔:规则载荷里可能有 |(正则)
        print(f'{c["rule"]},{c["rulePayload"]}\t{">".join(c["chains"])}')
        sys.exit(0)
EOF
}

# chains 形如 "sg>sg" 或 "TAILSCALE";期望出口出现在链上即通过
check() {  # check <描述> <期望> <lookup 结果>
  local desc=$1 want=$2 got=$3 rule chain
  if [ -z "$got" ]; then bad "$desc: 没抓到连接(连接失败或太快关闭)"; return; fi
  rule=${got%%$'\t'*}; chain=${got#*$'\t'}
  case ">$chain>" in
    *">$want>"*) ok  "$desc -> $chain   [$rule]" ;;
    *)           bad "$desc -> $chain   [$rule],期望 $want" ;;
  esac
}

echo "== 进程规则 =="
for c in "${CASES_PROC[@]}"; do
  IFS='|' read -r name rel want <<<"$c"
  check "$name ($rel)" "$want" "$(lookup proc "$W/$rel")"
done

echo; echo "== 域名规则 =="
for c in "${CASES_DOMAIN[@]}"; do
  IFS='|' read -r host want <<<"$c"
  check "$host" "$want" "$(lookup host "$host")"
done

echo; echo "== 桌面 app 规则(静态检查 + 当前运行中的连接) =="
for c in "${CASES_APP[@]}"; do
  IFS='|' read -r prefix want <<<"$c"
  re="^${prefix//./\\.}"   # ^/Applications/Claude\.app/
  if grep -qF -- "PROCESS-PATH-REGEX,${re},${want}" "$CFG"; then
    ok "规则存在: PROCESS-PATH-REGEX,${re},${want}"
  else
    bad "缺少规则: PROCESS-PATH-REGEX,${re},${want}"
  fi
  live=$(python3 -I - "$SNAP" "$prefix" <<'EOF'
import json, sys
snap, prefix = sys.argv[1:]
seen = set()
for line in open(snap):
    line = line.strip()
    if not line:
        continue
    for c in json.loads(line).get("connections") or []:
        m = c["metadata"]
        if (m.get("processPath") or "").startswith(prefix):
            seen.add(f'{m.get("process")}\t{">".join(c["chains"])}\t{c["rule"]},{c["rulePayload"]}')
print("\n".join(sorted(seen)))
EOF
)
  if [ -z "$live" ]; then skp "  $prefix 当前没有连接(app 未运行,或走了系统代理)"; continue; fi
  while IFS=$'\t' read -r proc chain rule; do
    case ">$chain>" in
      *">$want>"*) ok  "  $proc -> $chain   [$rule]" ;;
      *)           bad "  $proc -> $chain   [$rule],期望 $want" ;;
    esac
  done <<<"$live"
done

# ---- 系统代理会让 app 流量先进别的代理,进程规则就失效了
if [ "$(uname)" = Darwin ] && scutil --proxy | grep -q 'HTTPSEnable : 1'; then
  echo
  echo "注意: 系统 HTTPS 代理已开启($(scutil --proxy | awk '/HTTPSProxy/{h=$3} /HTTPSPort/{p=$3} END{print h":"p}'))," \
       "遵循系统代理的 app 在 mihomo 里会显示为代理程序本身,上面的 app 进程规则对它们不生效"
fi

[ $VERBOSE = 1 ] && { echo; echo "== 抓到的连接 =="; python3 -I -c '
import json,sys
seen=set()
for l in open(sys.argv[1]):
    l=l.strip()
    if not l: continue
    for c in json.loads(l).get("connections") or []:
        m=c["metadata"]; k=(m.get("process"),m.get("host") or m.get("sniffHost") or m.get("destinationIP"),c["rule"],">".join(c["chains"]))
        if k not in seen: seen.add(k); print(*k, sep=" | ")' "$SNAP"; }

echo
echo "结果: $pass 通过, $fail 失败, $skip 跳过"
[ $fail = 0 ]
