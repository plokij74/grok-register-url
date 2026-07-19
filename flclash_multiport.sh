#!/usr/bin/env bash
# FlClash → local multiport bridge (mihomo) → GrokX proxies.txt
#
# Each subscription node is bound to 127.0.0.1:7901+
# On every start/restart: probe ALL ports, write ONLY working ones to proxies.txt
#
# Usage:
#   ./flclash_multiport.sh start|stop|restart|status|regen|test
#
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

CONFIG="${GROKX_MULTIPORT_CONFIG:-$ROOT/flclash_multiport.yaml}"
CANDIDATES="${GROKX_MULTIPORT_CANDIDATES:-$ROOT/flclash_multiport.candidates.txt}"
BIN_DIR="$ROOT/.mihomo"
BIN="$BIN_DIR/mihomo"
PID_FILE="$BIN_DIR/mihomo.pid"
LOG_FILE="$BIN_DIR/mihomo.log"
PROFILE="${GROKX_FLCLASH_PROFILE:-$HOME/.local/share/com.follow.clash/profiles/336177297482584064.yaml}"
BASE_PORT="${GROKX_MULTIPORT_BASE:-7901}"
TEST_URL="${GROKX_PROXY_TEST_URL:-https://api.ipify.org}"
TEST_TIMEOUT="${GROKX_PROXY_TEST_TIMEOUT:-2}"
TEST_PARALLEL="${GROKX_PROXY_TEST_PARALLEL:-8}"
INCLUDE_FLCLASH_MAIN="${GROKX_INCLUDE_FLCLASH_7890:-1}"  # 1=also test 7890
FLCLASH_MAIN="${GROKX_FLCLASH_MAIN:-http://127.0.0.1:7890}"

log() { echo "[multiport] $*"; }

need_python() {
  command -v python3 >/dev/null || { log "python3 required"; exit 1; }
}

need_curl() {
  command -v curl >/dev/null || { log "curl required"; exit 1; }
}

regen_config() {
  need_python
  if [[ ! -f "$PROFILE" ]]; then
    log "FlClash profile not found: $PROFILE"
    exit 1
  fi
  GROKX_ROOT="$ROOT" \
  GROKX_FLCLASH_PROFILE="$PROFILE" \
  GROKX_MULTIPORT_BASE="$BASE_PORT" \
  GROKX_MULTIPORT_CANDIDATES="$CANDIDATES" \
  GROKX_MULTIPORT_CONFIG="$CONFIG" \
  python3 - <<'PY'
import os, re
from pathlib import Path

profile = Path(os.environ["GROKX_FLCLASH_PROFILE"])
root = Path(os.environ.get("GROKX_ROOT", "."))
base_port = int(os.environ.get("GROKX_MULTIPORT_BASE", "7901"))
cfg_path = Path(os.environ.get("GROKX_MULTIPORT_CONFIG", root / "flclash_multiport.yaml"))
cand_path = Path(os.environ.get("GROKX_MULTIPORT_CANDIDATES", root / "flclash_multiport.candidates.txt"))

text = profile.read_text(encoding="utf-8", errors="replace")
block_pat = re.compile(r"-\s*(\{[^{}]+\})")

def grab(body: str, key: str):
    mm = re.search(key + r":\s*'([^']*)'", body)
    if mm:
        return mm.group(1)
    mm = re.search(key + r":\s*([^,}\n]+)", body)
    return mm.group(1).strip() if mm else None

junk_kw = (
    "剩余流量", "距离下次", "套餐到期", "过期", "重置", "官网", "购买",
    "电报", "TG", "流量", "到期",
)
nodes = []
for m in block_pat.finditer(text):
    raw = m.group(1)
    b = raw[1:-1] if raw.startswith("{") else raw
    typ = grab(b, "type")
    name = grab(b, "name")
    if typ != "hysteria2" or not name:
        continue
    if any(k in name for k in junk_kw):
        continue
    nodes.append({"name": name, "raw_block": raw})

if not nodes:
    raise SystemExit("no hysteria2 nodes parsed from profile")

listeners = []
cand_lines = []
for i, n in enumerate(nodes):
    port = base_port + i
    listeners.append(
        f"  - name: grokx-p{port}\n"
        f"    type: mixed\n"
        f"    port: {port}\n"
        f"    listen: 127.0.0.1\n"
        f"    proxy: '{n['name']}'\n"
    )
    # url | name
    cand_lines.append(f"http://127.0.0.1:{port}\t{n['name']}")

yaml_text = f"""# Auto-generated multiport bridge from FlClash profile
# Profile: {profile.name}
# Nodes: {len(nodes)}  ports: {base_port}-{base_port + len(nodes) - 1}
# Start: ./flclash_multiport.sh start  (auto-tests, writes only live nodes to proxies.txt)

mixed-port: 0
port: 0
socks-port: 0
allow-lan: false
mode: rule
log-level: warning
ipv6: false
external-controller: 127.0.0.1:19090
find-process-mode: off
unified-delay: true
tcp-concurrent: true

dns:
  enable: true
  listen: 0.0.0.0:0
  enhanced-mode: fake-ip
  fake-ip-range: 198.19.0.1/16
  nameserver:
    - 223.5.5.5
    - 8.8.8.8

proxies:
"""
for n in nodes:
    yaml_text += f"  - {n['raw_block']}\n"

yaml_text += "\nproxy-groups:\n  - name: GLOBAL\n    type: select\n    proxies:\n"
for n in nodes:
    yaml_text += f"      - '{n['name']}'\n"
yaml_text += "      - DIRECT\n\nlisteners:\n"
yaml_text += "".join(listeners)
yaml_text += "\nrules:\n  - MATCH,DIRECT\n"

cfg_path.write_text(yaml_text, encoding="utf-8")
cand_path.write_text(
    "# url<TAB>node-name  (all candidates; live filter → proxies.txt)\n"
    + "\n".join(cand_lines)
    + "\n",
    encoding="utf-8",
)
print(f"nodes={len(nodes)} config={cfg_path} candidates={cand_path}")
for i, n in enumerate(nodes):
    print(f"  {base_port + i} -> {n['name']}")
PY
  log "regen done → $CONFIG + $CANDIDATES"
  log "proxies.txt NOT updated yet (run start/test to live-filter)"
}

ensure_bin() {
  mkdir -p "$BIN_DIR"
  if [[ -x "$BIN" ]]; then
    return 0
  fi
  log "downloading mihomo (Clash Meta) into $BIN_DIR ..."
  local ver arch url tmp
  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64) arch="amd64" ;;
    aarch64|arm64) arch="arm64" ;;
    *) log "unsupported arch: $arch"; exit 1 ;;
  esac
  ver="${MIHOMO_VERSION:-v1.19.12}"
  url="https://github.com/MetaCubeX/mihomo/releases/download/${ver}/mihomo-linux-${arch}-${ver}.gz"
  tmp="$BIN_DIR/mihomo.gz"
  if command -v curl >/dev/null; then
    curl -fsSL "$url" -o "$tmp"
  else
    wget -qO "$tmp" "$url"
  fi
  gzip -dc "$tmp" > "$BIN"
  chmod +x "$BIN"
  rm -f "$tmp"
  log "mihomo ready: $($BIN -v 2>/dev/null || true)"
}

is_running() {
  if [[ -f "$PID_FILE" ]]; then
    local pid
    pid="$(cat "$PID_FILE" 2>/dev/null || true)"
    if [[ -n "${pid:-}" ]] && kill -0 "$pid" 2>/dev/null; then
      return 0
    fi
  fi
  return 1
}

wait_ports() {
  # wait until at least one multiport is open (max ~8s)
  local i p
  for i in $(seq 1 16); do
    p="$BASE_PORT"
    if (echo >/dev/tcp/127.0.0.1/"$p") >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.5
  done
  return 1
}

# Parallel probe all candidates with Python (reliable); write live-only proxies.txt
filter_live_proxies() {
  need_curl
  need_python

  if [[ ! -f "$CANDIDATES" ]]; then
    log "no candidates file — regen first"
    regen_config
  fi

  log "probing all nodes (timeout=${TEST_TIMEOUT}s parallel≤${TEST_PARALLEL}) → $TEST_URL"

  GROKX_ROOT="$ROOT" \
  GROKX_MULTIPORT_CANDIDATES="$CANDIDATES" \
  GROKX_PROXY_TEST_URL="$TEST_URL" \
  GROKX_PROXY_TEST_TIMEOUT="$TEST_TIMEOUT" \
  GROKX_PROXY_TEST_PARALLEL="$TEST_PARALLEL" \
  GROKX_INCLUDE_FLCLASH_7890="$INCLUDE_FLCLASH_MAIN" \
  GROKX_FLCLASH_MAIN="$FLCLASH_MAIN" \
  python3 - <<'PY'
from __future__ import annotations

import os
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

root = Path(os.environ.get("GROKX_ROOT", "."))
cand_path = Path(os.environ["GROKX_MULTIPORT_CANDIDATES"])
out_path = root / "proxies.txt"
test_url = os.environ.get("GROKX_PROXY_TEST_URL", "https://api.ipify.org")
timeout = float(os.environ.get("GROKX_PROXY_TEST_TIMEOUT", "2"))
parallel = max(1, int(os.environ.get("GROKX_PROXY_TEST_PARALLEL", "8")))
include_main = os.environ.get("GROKX_INCLUDE_FLCLASH_7890", "1") == "1"
main_url = os.environ.get("GROKX_FLCLASH_MAIN", "http://127.0.0.1:7890")

candidates: list[tuple[str, str]] = []
for line in cand_path.read_text(encoding="utf-8", errors="replace").splitlines():
    line = line.strip()
    if not line or line.startswith("#"):
        continue
    if "\t" in line:
        url, name = line.split("\t", 1)
    else:
        parts = line.split(None, 1)
        url = parts[0]
        name = parts[1] if len(parts) > 1 else ""
        if name.startswith("#"):
            name = name[1:].strip()
    url = url.strip()
    name = name.strip()
    if url.startswith("http://") or url.startswith("socks5"):
        candidates.append((url, name))

if include_main:
    candidates.append((main_url, "FlClash-main-7890"))

ip_re = re.compile(r"^[0-9a-fA-F.:]+$")


def probe(url: str, name: str) -> tuple[str, str, str, str]:
    try:
        r = subprocess.run(
            ["curl", "-sS", "-m", str(timeout), "-x", url, test_url],
            capture_output=True,
            text=True,
            timeout=timeout + 3,
        )
        ip = (r.stdout or "").strip()
        if r.returncode == 0 and ip and ip_re.match(ip):
            return ("OK", url, ip, name)
    except Exception:
        pass
    return ("FAIL", url, "", name)


rows: list[tuple[str, str, str, str]] = []
with ThreadPoolExecutor(max_workers=parallel) as ex:
    futs = [ex.submit(probe, u, n) for u, n in candidates]
    for fut in as_completed(futs):
        rows.append(fut.result())


def sort_key(r: tuple[str, str, str, str]):
    u = r[1]
    if u.startswith("http://127.0.0.1:"):
        try:
            return (0, int(u.rsplit(":", 1)[-1]))
        except ValueError:
            return (1, u)
    return (1, u)


ok = sorted([r for r in rows if r[0] == "OK"], key=sort_key)
fail = sorted([r for r in rows if r[0] != "OK"], key=sort_key)

print()
print(f"[multiport] probe summary: ok={len(ok)} fail={len(fail)}")
for st, url, ip, name in ok + fail:
    if st == "OK":
        print(f"  OK   {url}  ip={ip}  # {name}")
    else:
        print(f"  FAIL {url}  # {name}")

ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
lines = [
    "# Auto-selected LIVE proxies from FlClash multiport bridge",
    f"# Generated: {ts}  ok={len(ok)} fail={len(fail)}",
    "# Bridge: ./flclash_multiport.sh start|restart  (re-tests every time)",
    "# Candidates: flclash_multiport.candidates.txt",
    "",
]
if not ok:
    lines += [
        "# WARNING: no live proxy passed the test!",
        "# Fallback single exit (may still work for some traffic):",
        f"{main_url}  # FlClash-main fallback",
        "",
    ]
else:
    for st, url, ip, name in ok:
        note = name or ""
        if ip:
            lines.append(f"{url}  # {note} ip={ip}".rstrip())
        else:
            lines.append(f"{url}  # {note}".rstrip())
    lines.append("")
    if fail:
        lines.append("# --- failed this probe (not used) ---")
        for st, url, ip, name in fail:
            lines.append(f"# {url}  # {name}")
        lines.append("")

out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
print(f"wrote {out_path} live={len(ok)} dead={len(fail)}")
raise SystemExit(0 if ok else 2)
PY
  local rc=$?
  if [[ $rc -ne 0 ]]; then
    log "WARNING: zero live nodes — proxies.txt has fallback only"
    return 1
  fi
  log "proxies.txt updated with live nodes only"
  return 0
}

cmd_start() {
  # always refresh config from latest FlClash profile
  if [[ ! -f "$PROFILE" ]]; then
    log "FlClash profile missing: $PROFILE"
    exit 1
  fi
  log "regen from FlClash profile..."
  regen_config

  if is_running; then
    log "bridge already running pid=$(cat "$PID_FILE") — re-probe only"
  else
    ensure_bin
    : >"$LOG_FILE"
    log "starting mihomo with $CONFIG"
    nohup "$BIN" -f "$CONFIG" -d "$BIN_DIR" >>"$LOG_FILE" 2>&1 &
    echo $! >"$PID_FILE"
    if ! wait_ports; then
      log "ports not open — see $LOG_FILE"
      tail -n 40 "$LOG_FILE" || true
      exit 1
    fi
    log "started pid=$(cat "$PID_FILE")"
  fi

  # brief warm-up so hy2 handshakes settle
  sleep 1
  filter_live_proxies || true
  cmd_status
}

cmd_stop() {
  if is_running; then
    local pid
    pid="$(cat "$PID_FILE")"
    kill "$pid" 2>/dev/null || true
    sleep 0.5
    kill -9 "$pid" 2>/dev/null || true
    rm -f "$PID_FILE"
    log "stopped $pid"
  else
    log "not running"
    rm -f "$PID_FILE"
  fi
}

cmd_status() {
  if is_running; then
    log "running pid=$(cat "$PID_FILE")"
  else
    log "not running"
  fi
  if [[ -f "$ROOT/proxies.txt" ]]; then
    local n
    n="$(grep -cE '^[[:space:]]*http://' "$ROOT/proxies.txt" || true)"
    log "proxies.txt live lines: $n"
    grep -E '^[[:space:]]*http://' "$ROOT/proxies.txt" 2>/dev/null | sed 's/^/  /' || true
  fi
  local open=0
  local p
  for p in $(seq "$BASE_PORT" $((BASE_PORT + 30))); do
    if (echo >/dev/tcp/127.0.0.1/"$p") >/dev/null 2>&1; then
      open=$((open + 1))
    else
      # stop after first closed beyond base if none yet? keep scanning range
      :
    fi
  done
  log "open multiport listeners (scan $BASE_PORT..$((BASE_PORT+30))): $open"
}

cmd_test() {
  # re-test candidates without restarting; refresh proxies.txt
  if ! is_running; then
    log "bridge not running — starting first"
    cmd_start
    return
  fi
  if [[ ! -f "$CANDIDATES" ]]; then
    regen_config
  fi
  filter_live_proxies
}

usage() {
  cat <<EOF
Usage: $0 {start|stop|restart|status|regen|test}

  start    regen from FlClash → start mihomo → probe ALL nodes → proxies.txt (live only)
  restart  stop + start (full re-probe)
  stop     stop multiport bridge
  status   pid + current live proxies.txt
  regen    only rebuild yaml/candidates (no probe)
  test     probe again (bridge must be up) → refresh proxies.txt

Env:
  GROKX_PROXY_TEST_TIMEOUT=2      per-node curl timeout seconds
  GROKX_PROXY_TEST_PARALLEL=8     parallel probes
  GROKX_INCLUDE_FLCLASH_7890=1    also test http://127.0.0.1:7890
  GROKX_PROXY_TEST_URL=https://api.ipify.org

GrokX: after start, restart registration; 代理=Y, Roxy代理=N.
EOF
}

case "${1:-}" in
  regen) regen_config ;;
  start) cmd_start ;;
  stop) cmd_stop ;;
  restart) cmd_stop; cmd_start ;;
  status) cmd_status ;;
  test) cmd_test ;;
  *) usage; exit 1 ;;
esac
