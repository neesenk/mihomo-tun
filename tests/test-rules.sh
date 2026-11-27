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
# 期望结果不写死:按生成的 config.yaml 里的 rules(含 sub-rules),用每条连接自己的
# 进程/域名/目的 IP 推算应命中的规则,再和 mihomo 实际报告的规则、出口链比较。
# 无法离线判断的规则(GEOIP、RULE-SET、需要解析域名的 IP-CIDR 等)视为"可能命中",
# 实际命中它们中的任何一条或之后第一条确定命中的规则都算通过。
# macOS 上另外检查当前运行中的 /Applications 下 app 的连接。
#
# 用例表在下面 CASES_PROC / CASES_DOMAIN,只决定发起哪些连接。
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

# 进程用例: 名称|相对测试目录的程序路径
CASES_PROC=(
  "Claude Code CLI|.local/share/claude/versions/9.9.9"
  "Codex CLI|bin/codex"
  "agy CLI|bin/agy"
  "Codex 运行时|.codex/bin/node"
  "对照: 普通进程|bin/plain-curl"
)
# 域名用例
CASES_DOMAIN=(
  api.anthropic.com claude.ai api.openai.com chatgpt.com cdn.oaistatic.com
  sora.com clau.de cdn.auth0.com api.segment.io
  www.google.com github.com www.youtube.com git.garena.com www.baidu.com speed.cloudflare.com
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
  IFS='|' read -r _ rel <<<"$c"
  mkdir -p "$W/$(dirname "$rel")"; cp /usr/bin/curl "$W/$rel"
  # macOS 上复制出来的系统二进制签名失效会被直接 kill,需要重新 ad-hoc 签名
  [ "$(uname)" = Darwin ] && codesign --force -s - "$W/$rel" 2>/dev/null
  "$W/$rel" -s -o /dev/null -m 8 --limit-rate 20k "$HOLD_URL" &
  PIDS+=($!); disown $!
done
for host in "${CASES_DOMAIN[@]}"; do
  ( sleep 6 | openssl s_client -connect "$host:443" -servername "$host" -quiet >/dev/null 2>&1 ) &
  PIDS+=($!); disown $!
done

# ---- 连接期间多次抓取 /connections(连接可能很快关闭)
for _ in 1 2 3 4 5 6; do
  sleep 0.7
  curl -fsS -m 3 -H "$AUTH" "$API/connections" >>"$SNAP" && echo >>"$SNAP"
done

# ---- 按 config.yaml 推算并比较,输出 "状态<TAB>文字" 或 "#<TAB>小节标题"
evaluate() {
  local c name rel
  {
    for c in "${CASES_PROC[@]}"; do IFS='|' read -r name rel <<<"$c"; printf 'proc\t%s (%s)\t%s\n' "$name" "$rel" "$W/$rel"; done
    for c in "${CASES_DOMAIN[@]}"; do printf 'host\t%s\t%s\n' "$c" "$c"; done
  } >"$W/cases.tsv"
  python3 -I - "$CFG" "$SNAP" "$W/cases.tsv" "$(uname)" "$VERBOSE" <<'EOF'
import ipaddress, json, re, sys

cfg, snap, cases_file, osname, verbose = sys.argv[1:]

# ---------- 解析 config.yaml 的 rules / sub-rules(脚本生成,格式固定,不依赖 PyYAML)
def strip_item(line):
    v = line.strip()[2:].strip()
    v = re.sub(r"\s+#.*$", "", v)
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
        v = v[1:-1]
    return v

rules, subs, section, subname = [], {}, None, None
for raw in open(cfg):
    line = raw.rstrip("\n")
    if re.match(r"^[A-Za-z][\w-]*:", line):
        section = line.split(":")[0]; subname = None; continue
    if section == "rules" and re.match(r"^\s*- ", line):
        rules.append(strip_item(line))
    elif section == "sub-rules":
        m = re.match(r"^  ([^\s#-][^:]*):\s*$", line)
        if m:
            subname = m.group(1).strip(); subs[subname] = []
        elif subname and re.match(r"^\s*- ", line):
            subs[subname].append(strip_item(line))

def split_rule(r):
    """-> (类型, 载荷, 目标, 参数列表);载荷可能是带逗号的 (...) 组"""
    typ, _, rest = r.partition(",")
    typ = typ.strip().upper()
    if typ == "MATCH":
        return typ, "", rest.strip(), []
    if rest.startswith("("):
        depth = 0
        for i, ch in enumerate(rest):
            depth += ch == "("; depth -= ch == ")"
            if depth == 0:
                break
        payload, rest = rest[: i + 1], rest[i + 2:]
    else:
        payload, _, rest = rest.partition(",")
    parts = [x.strip() for x in rest.split(",")] if rest else [""]
    return typ, payload.strip(), parts[0], parts[1:]

# ---------- 单条规则是否命中: True / False / None(无法离线判断)
FAKE_NET = ipaddress.ip_network("198.18.0.0/15")

def match(typ, payload, params, m):
    host = (m["rulehost"] or "").lower().rstrip(".")
    pl = payload.lower()
    proc, path = m.get("process") or "", m.get("processPath") or ""
    if typ == "DOMAIN":          return bool(host) and host == pl
    if typ == "DOMAIN-SUFFIX":   return bool(host) and (host == pl or host.endswith("." + pl))
    if typ == "DOMAIN-KEYWORD":  return bool(host) and pl in host
    if typ == "DOMAIN-REGEX":    return bool(host) and re.search(payload, host, re.I) is not None
    if typ == "PROCESS-NAME":    return proc == payload
    if typ == "PROCESS-PATH":    return path == payload
    if typ == "PROCESS-NAME-REGEX": return re.search(payload, proc, re.I) is not None
    if typ == "PROCESS-PATH-REGEX": return re.search(payload, path, re.I) is not None
    if typ in ("IP-CIDR", "IP-CIDR6"):
        ip = m["ip"]
        if ip is None:
            # fake-ip 连接一开始没有 IP:no-resolve 不匹配;否则 mihomo 会解析域名,离线无法判断
            return False if "no-resolve" in params else None
        try:
            return ip in ipaddress.ip_network(payload, strict=False)
        except ValueError:
            return None
    if typ == "DST-PORT":
        port = int(m.get("destinationPort") or 0)
        for part in payload.split("/"):
            lo, _, hi = part.partition("-")
            if lo.isdigit() and int(lo) <= port <= int(hi or lo):
                return True
        return False
    if typ == "NETWORK":         return (m.get("network") or "").lower() == pl
    if typ == "SUB-RULE":
        inner = payload.strip()[1:-1]
        t, p, _, prm = split_rule(inner + ",X")
        return match(t, p, prm, m)
    if typ == "MATCH":           return True
    return None  # GEOIP / GEOSITE / RULE-SET / AND / OR / NOT 等

def norm_type(t):
    return {"SUB-RULE": "subrules"}.get(t, t.replace("-", "").lower())

def predict(rule_list, m):
    """-> 候选列表 [(类型, 载荷, 目标, 确定?)],最后一个是第一条确定命中的规则"""
    cands = []
    for r in rule_list:
        typ, payload, target, params = split_rule(r)
        hit = match(typ, payload, params, m)
        if hit is False:
            continue
        if typ == "SUB-RULE" and hit:
            inner = predict(subs.get(target, []), m)
            cands += [(typ, payload, t, sure) for _, _, t, sure in inner]
            if inner and inner[-1][3]:
                return cands
            continue
        cands.append((typ, payload, target, hit is True))
        if hit:
            return cands
    return cands

def meta(c):
    m = dict(c["metadata"])
    m["rulehost"] = m.get("sniffHost") or m.get("host") or ""
    ip = None
    if not m.get("host") and m.get("destinationIP"):   # 非 fake-ip 连接,一开始就有真实 IP
        try:
            ip = ipaddress.ip_address(m["destinationIP"])
        except ValueError:
            pass
        if ip is not None and ip in FAKE_NET:
            ip = None
    m["ip"] = ip
    return m

def judge(desc, c):
    m = meta(c)
    cands = predict(rules, m)
    chain = ">".join(c["chains"])
    got_t, got_p = c["rule"], c["rulePayload"]
    got = f"{got_t},{got_p}" if got_p else got_t
    for typ, payload, target, _ in cands:
        same_rule = norm_type(typ) == got_t.lower() and (
            typ == "SUB-RULE" or payload.lower() == got_p.lower())
        if same_rule and target in c["chains"]:
            print(f"PASS\t{desc} -> {chain}   [{got}]")
            return
    want = " 或 ".join(f"[{t},{p}] -> {g}" if p else f"[{t}] -> {g}" for t, p, g, _ in cands) or "(没有可命中的规则)"
    print(f"FAIL\t{desc} -> {chain}   [{got}],按配置应为 {want}")

conns = []
for line in open(snap):
    line = line.strip()
    if line:
        conns += json.loads(line).get("connections") or []

def first(pred):
    return next((c for c in conns if pred(c["metadata"])), None)

sections = {"proc": "进程规则", "host": "域名规则"}
cur = None
for line in open(cases_file):
    kind, desc, val = line.rstrip("\n").split("\t")
    if kind != cur:
        cur = kind; print(f"#\t{sections[kind]}")
    if kind == "proc":
        c = first(lambda m: m.get("processPath") == val)
    else:
        # fake-ip 域名在 host 里;真实 IP 的连接由 sniffer 识别,域名在 sniffHost 里
        c = first(lambda m: val in (m.get("host"), m.get("sniffHost")) and m.get("process") == "openssl")
    if c is None:
        print(f"FAIL\t{desc}: 没抓到连接(连接失败或太快关闭)")
    else:
        judge(desc, c)

if osname == "Darwin":
    print("#\t运行中的 /Applications app 连接")
    seen = {}
    for c in conns:
        m = c["metadata"]
        if (m.get("processPath") or "").startswith("/Applications/"):
            key = (m.get("process"), m.get("sniffHost") or m.get("host") or m.get("destinationIP"))
            seen.setdefault(key, c)
    if not seen:
        print("SKIP\t当前没有 /Applications 下 app 的连接(app 未运行,或走了系统代理)")
    for (proc, host), c in sorted(seen.items(), key=lambda kv: str(kv[0])):
        judge(f"{proc} {host}", c)

if verbose == "1":
    print("#\t抓到的连接")
    seen = set()
    for c in conns:
        m = c["metadata"]
        k = (m.get("process"), m.get("host") or m.get("sniffHost") or m.get("destinationIP"), c["rule"], ">".join(c["chains"]))
        if k not in seen:
            seen.add(k); print("INFO\t" + " | ".join(map(str, k)))
EOF
}

first_section=1
while IFS=$'\t' read -r st msg; do
  case $st in
    '#')  [ $first_section = 1 ] || echo; first_section=0; echo "== $msg ==" ;;
    PASS) ok "$msg" ;;
    FAIL) bad "$msg" ;;
    SKIP) skp "$msg" ;;
    *)    echo "$msg" ;;
  esac
done < <(evaluate)

# ---- 系统代理会让 app 流量先进别的代理,进程规则就失效了
if [ "$(uname)" = Darwin ] && scutil --proxy | grep -q 'HTTPSEnable : 1'; then
  echo
  echo "注意: 系统 HTTPS 代理已开启($(scutil --proxy | awk '/HTTPSProxy/{h=$3} /HTTPSPort/{p=$3} END{print h":"p}'))," \
       "遵循系统代理的 app 在 mihomo 里会显示为代理程序本身,上面的 app 进程规则对它们不生效"
fi

echo
echo "结果: $pass 通过, $fail 失败, $skip 跳过"
[ $fail = 0 ]
