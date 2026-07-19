#!/bin/bash
# 一键启动 cpa_reactivate：交互选参数，回车=当前默认，选完写回 refresh.config
#
# 用法:
#   ./refresh.sh              # 交互菜单（TTY）
#   ./refresh.sh --yes        # 用 refresh.config 直接跑，不问
#   ./refresh.sh --print      # 只打印将执行的命令
#   ./refresh.sh --yes --print
#   ./refresh.sh -- ...       # 透传给 cpa_reactivate.py
#   ./refresh.sh --disabled --dry-run   # 带参则跳过菜单直跑
set -euo pipefail
cd "$(dirname "$0")"

PYTHON_EXE=".venv/bin/python"
if [ ! -f "$PYTHON_EXE" ]; then
    if ! command -v python3 &>/dev/null; then
        echo "[ERROR] Python not found. Run setup.sh first."
        exit 1
    fi
    PYTHON_EXE="python3"
fi

CFG_FILE="${GROKX_REFRESH_CONFIG:-refresh.config}"
export PYTHONUNBUFFERED=1
export GROKX_BROWSER_BACKEND_DIR="${GROKX_BROWSER_BACKEND_DIR:-$(pwd)}"

# -------- defaults (overridden by refresh.config) --------
FILTER="default"     # default|disabled|expired|reauth|all|local
DRY_RUN=0            # 0|1
WORKERS=2
BROWSER="headed"     # headed|headless|no-browser
METHOD="default"     # default|refresh-only|remint-only
NO_PUSH=0            # 0|1
LIMIT=0              # 0=不限
STALE_HOURS=6
MIN_FAILED=1
REPORT="cpa_reactivate.json"
LOG_FILE="cpa_reactivate.log"

MODE_YES=0
MODE_PRINT=0

load_cfg() {
    if [ -f "$CFG_FILE" ]; then
        set -a
        # shellcheck disable=SC1091
        source <(grep -E '^[A-Za-z_][A-Za-z0-9_]*=' "$CFG_FILE" || true)
        set +a
        echo "[*] loaded defaults from $CFG_FILE"
    else
        echo "[*] no $CFG_FILE yet; using built-in defaults"
    fi
}

save_cfg() {
    cat >"$CFG_FILE" <<EOF
# GrokX cpa_reactivate launcher defaults (managed by refresh.sh)
# 空行/回车 = 用这里的值；选完会写回本文件

FILTER=$FILTER
DRY_RUN=$DRY_RUN
WORKERS=$WORKERS
BROWSER=$BROWSER
METHOD=$METHOD
NO_PUSH=$NO_PUSH
LIMIT=$LIMIT
STALE_HOURS=$STALE_HOURS
MIN_FAILED=$MIN_FAILED
REPORT=$REPORT
LOG_FILE=$LOG_FILE
EOF
    echo "[*] saved defaults → $CFG_FILE"
}

# $1=prompt  $2=current  rest= "key:label"
ask_choice() {
    local prompt="$1"
    local current="$2"
    shift 2
    local keys=() labels=()
    local i=1 pair k v cur_idx=""
    for pair in "$@"; do
        k="${pair%%:*}"
        v="${pair#*:}"
        keys+=("$k")
        labels+=("$v")
        if [ "$k" = "$current" ]; then
            cur_idx=$i
        fi
        i=$((i + 1))
    done
    if [ -z "$cur_idx" ]; then
        cur_idx=1
        current="${keys[0]}"
    fi

    echo "" >&2
    echo "── $prompt  (回车=默认 [$cur_idx] ${labels[$((cur_idx - 1))]}) ──" >&2
    i=1
    for v in "${labels[@]}"; do
        if [ "$i" = "$cur_idx" ]; then
            printf "  %d) %s  ← 默认\n" "$i" "$v" >&2
        else
            printf "  %d) %s\n" "$i" "$v" >&2
        fi
        i=$((i + 1))
    done
    local ans
    while true; do
        printf "选择 [1-%d，回车默认]: " "${#keys[@]}" >&2
        # 必须从 /dev/tty 读，避免管道/重定向抢 stdin
        if ! read -r ans </dev/tty; then
            ans=""
        fi
        if [ -z "$ans" ]; then
            echo "$current"
            return
        fi
        if [[ "$ans" =~ ^[0-9]+$ ]] && [ "$ans" -ge 1 ] && [ "$ans" -le "${#keys[@]}" ]; then
            echo "${keys[$((ans - 1))]}"
            return
        fi
        echo "  无效，请输入 1-${#keys[@]} 或回车" >&2
    done
}

ask_number() {
    local prompt="$1"
    local current="$2"
    local min="${3:-0}"
    local ans
    echo "" >&2
    echo "── $prompt  (回车=默认 [$current]) ──" >&2
    while true; do
        printf "输入数字 [回车默认 %s]: " "$current" >&2
        if ! read -r ans </dev/tty; then
            ans=""
        fi
        if [ -z "$ans" ]; then
            echo "$current"
            return
        fi
        if [[ "$ans" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
            if [[ "$ans" =~ ^[0-9]+$ ]] && [ "$ans" -lt "$min" ]; then
                echo "  需 >= $min" >&2
                continue
            fi
            echo "$ans"
            return
        fi
        echo "  请输入数字" >&2
    done
}

ask_text() {
    local prompt="$1"
    local current="$2"
    local ans
    echo "" >&2
    echo "── $prompt  (回车=默认 [$current]) ──" >&2
    printf "输入 [回车默认]: " >&2
    if ! read -r ans </dev/tty; then
        ans=""
    fi
    if [ -z "$ans" ]; then
        echo "$current"
    else
        echo "$ans"
    fi
}

confirm_run() {
    local ans
    echo ""
    echo "════════════════════════════════════"
    echo " 即将执行："
    echo "   $*"
    echo "════════════════════════════════════"
    if [ "$MODE_YES" = "1" ]; then
        return 0
    fi
    printf "开始? [Y/n，回车=Y]: "
    if ! read -r ans </dev/tty; then
        ans=""
    fi
    case "${ans:-Y}" in
        y|Y|yes|YES|"") return 0 ;;
        *) echo "已取消"; return 1 ;;
    esac
}

# 根据当前变量填充全局数组 CMD
build_cmd_array() {
    CMD=("$PYTHON_EXE" -u cpa_reactivate.py)
    case "$FILTER" in
        disabled) CMD+=(--disabled) ;;
        expired) CMD+=(--expired) ;;
        reauth|inspection) CMD+=(--from-inspection reauth) ;;
        all) CMD+=(--all) ;;
        local) CMD+=(--local-only --expired) ;;
        default|"") ;;
        *) echo "[WARN] unknown FILTER=$FILTER, ignore" >&2 ;;
    esac
    case "$METHOD" in
        refresh-only) CMD+=(--refresh-only) ;;
        remint-only) CMD+=(--remint-only) ;;
        default|"") ;;
    esac
    case "$BROWSER" in
        headed) CMD+=(--headed) ;;
        headless) CMD+=(--headless) ;;
        no-browser) CMD+=(--no-browser) ;;
        default|"") ;;
    esac
    if [ "${DRY_RUN:-0}" = "1" ]; then
        CMD+=(--dry-run)
    fi
    if [ "${NO_PUSH:-0}" = "1" ]; then
        CMD+=(--no-push)
    fi
    if [ "${WORKERS:-0}" -gt 0 ] 2>/dev/null; then
        CMD+=(--workers "$WORKERS")
    fi
    if [ "${LIMIT:-0}" -gt 0 ] 2>/dev/null; then
        CMD+=(--limit "$LIMIT")
    fi
    CMD+=(--stale-hours "$STALE_HOURS")
    CMD+=(--min-failed "$MIN_FAILED")
    if [ -n "${REPORT:-}" ] && [[ "$REPORT" == *.json ]]; then
        CMD+=(--report "$REPORT")
    fi
}

run_cmd() {
    echo ""
    echo "Starting CPA reactivate (console + $LOG_FILE)..."
    echo "==== $(date '+%F %T') start pid=$$ filter=$FILTER dry=$DRY_RUN workers=$WORKERS ====" >>"$LOG_FILE"
    echo "cmd: ${CMD[*]}" >>"$LOG_FILE"

    set +e
    "${CMD[@]}" 2>&1 | tee -a "$LOG_FILE"
    EXIT_CODE=${PIPESTATUS[0]}
    set -e

    echo "==== $(date '+%F %T') exit=$EXIT_CODE ====" >>"$LOG_FILE"
    echo ""
    if [ "$EXIT_CODE" -ne 0 ]; then
        echo "Program exited with code $EXIT_CODE. See $LOG_FILE"
    else
        echo "Done. log=$LOG_FILE${REPORT:+ report=$REPORT}"
    fi
    exit "$EXIT_CODE"
}

usage() {
    cat <<'EOF'
用法:
  ./refresh.sh                 交互选参数（回车=默认），保存 refresh.config 后运行
  ./refresh.sh --yes           用 refresh.config 直接跑，不弹菜单
  ./refresh.sh --print         只打印命令（可加 --yes）
  ./refresh.sh -- --disabled   透传参数给 cpa_reactivate.py
  ./refresh.sh --disabled ...  带 cpa 参数则跳过菜单直跑

配置文件: refresh.config（同目录，可用 GROKX_REFRESH_CONFIG 覆盖）
EOF
}

# -------- parse launcher flags first --------
PASS_ARGS=()
while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help)
            usage
            exit 0
            ;;
        --yes|-y)
            MODE_YES=1
            shift
            ;;
        --print|--dry-cmd)
            MODE_PRINT=1
            shift
            ;;
        --)
            shift
            PASS_ARGS=("$@")
            break
            ;;
        *)
            # 其余视为透传给 cpa_reactivate
            PASS_ARGS=("$@")
            break
            ;;
    esac
done

# 透传模式：不读菜单配置，直接跑
if [ ${#PASS_ARGS[@]} -gt 0 ]; then
    LOG_FILE="${GROKX_REFRESH_LOG:-cpa_reactivate.log}"
    if [ "$MODE_PRINT" = "1" ]; then
        printf '%q ' "$PYTHON_EXE" -u cpa_reactivate.py "${PASS_ARGS[@]}"
        echo
        exit 0
    fi
    echo "==== $(date '+%F %T') refresh passthrough pid=$$ ====" >>"$LOG_FILE"
    echo "Starting: $PYTHON_EXE cpa_reactivate.py ${PASS_ARGS[*]}"
    set +e
    "$PYTHON_EXE" -u cpa_reactivate.py "${PASS_ARGS[@]}" 2>&1 | tee -a "$LOG_FILE"
    EXIT_CODE=${PIPESTATUS[0]}
    set -e
    echo "==== $(date '+%F %T') exit=$EXIT_CODE ====" >>"$LOG_FILE"
    exit "$EXIT_CODE"
fi

load_cfg

# --yes：加载配置后直接跑 / 打印
if [ "$MODE_YES" = "1" ]; then
    build_cmd_array
    if [ "$MODE_PRINT" = "1" ]; then
        printf '%q ' "${CMD[@]}"
        echo
        exit 0
    fi
    if ! confirm_run "${CMD[*]}"; then
        exit 0
    fi
    run_cmd
fi

# 交互菜单需要真正的 TTY
if [ ! -t 0 ] && [ ! -e /dev/tty ]; then
    echo "[ERROR] refresh.sh 交互模式需要终端。"
    echo "  无菜单请用: ./refresh.sh --yes"
    echo "  或直跑:    $PYTHON_EXE cpa_reactivate.py --disabled --dry-run"
    exit 1
fi
if [ ! -c /dev/tty ]; then
    echo "[ERROR] 无 /dev/tty，无法交互。用 ./refresh.sh --yes"
    exit 1
fi

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║   GrokX CPA 续号 / refresh 一键启动      ║"
echo "╚══════════════════════════════════════════╝"
echo "  配置文件: $CFG_FILE"
echo "  每项回车 = 保留当前默认；选完会保存"
echo "  快速跳过: ./refresh.sh --yes"

FILTER=$(ask_choice "筛选范围 FILTER" "$FILTER" \
    "default:默认 dead（过期/无刷新/停用/不可用等）" \
    "reauth:巡检需重登 --from-inspection reauth（≠停用）" \
    "disabled:只看停用 --disabled（常=额度用完）" \
    "expired:只看过期 token --expired" \
    "all:全部远程/本地 --all（慎用）" \
    "local:仅本地过期 --local-only --expired")

DRY_RUN=$(ask_choice "运行模式 DRY_RUN" "$DRY_RUN" \
    "0:真跑 refresh/remint + 推送" \
    "1:只扫描 dry-run（不改号不推送）")

WORKERS=$(ask_number "并发 workers（refresh 建议 2–4；Roxy CF 建议 1–2）" "$WORKERS" 1)

BROWSER=$(ask_choice "浏览器 / Turnstile BROWSER" "$BROWSER" \
    "headed:有头 Chromium --headed" \
    "headless:无头 --headless" \
    "no-browser:不跑 CF（仅 refresh，协议 remint 会停）")

METHOD=$(ask_choice "恢复路径 METHOD" "$METHOD" \
    "default:先 refresh，失败再 protocol remint" \
    "refresh-only:只 refresh_token" \
    "remint-only:跳过 refresh，强制 CF+CreateSession")

NO_PUSH=$(ask_choice "推送到远程 CPA" "$NO_PUSH" \
    "0:推送（默认）" \
    "1:不推送 --no-push（只写本地）")

LIMIT=$(ask_number "数量上限 LIMIT（0=不限制）" "$LIMIT" 0)
STALE_HOURS=$(ask_number "stale-hours（last_refresh 过旧阈值小时）" "$STALE_HOURS" 0)
MIN_FAILED=$(ask_number "min-failed（配合 stale 的 failed 阈值）" "$MIN_FAILED" 0)

# 推荐日志名（用户可覆盖）
if [ "$DRY_RUN" = "1" ]; then
    suggest_log="cpa_reactivate_dryrun.log"
else
    case "$FILTER" in
        disabled) suggest_log="cpa_reactivate_disabled.log" ;;
        reauth|inspection) suggest_log="cpa_reactivate_reauth.log" ;;
        expired) suggest_log="cpa_reactivate_expired.log" ;;
        all) suggest_log="cpa_reactivate_all.log" ;;
        local) suggest_log="cpa_reactivate_local.log" ;;
        *) suggest_log="cpa_reactivate.log" ;;
    esac
fi
echo ""
echo "（推荐日志: $suggest_log）"
LOG_FILE=$(ask_text "日志文件 LOG_FILE" "${LOG_FILE:-$suggest_log}")

if [ -z "${REPORT:-}" ] || [[ "$REPORT" != *.json ]]; then
    REPORT="${LOG_FILE%.log}.json"
fi
echo ""
echo "（输入 - 关闭 JSON report）"
_rep=$(ask_text "JSON report 路径" "$REPORT")
if [ "$_rep" = "-" ]; then
    REPORT=""
else
    REPORT="$_rep"
fi

save_cfg
build_cmd_array

if [ "$MODE_PRINT" = "1" ]; then
    printf '%q ' "${CMD[@]}"
    echo
    exit 0
fi

if ! confirm_run "${CMD[*]}"; then
    exit 0
fi
run_cmd
