#!/bin/bash
cd "$(dirname "$0")"

PYTHON_EXE=".venv/bin/python"
if [ ! -f "$PYTHON_EXE" ]; then
    if ! command -v python3 &> /dev/null; then
        echo "[ERROR] Python not found. Run setup.sh first."
        exit 1
    fi
    PYTHON_EXE="python3"
fi

LOG_FILE="${GROKX_LOG_FILE:-register.log}"
# tee console + file; keep interactive stdin for --cli menu
export PYTHONUNBUFFERED=1
# Roxy backend module lives next to this script (browser_backend.py)
export GROKX_BROWSER_BACKEND_DIR="${GROKX_BROWSER_BACKEND_DIR:-$(cd "$(dirname "$0")" && pwd)}"

echo "Starting GrokX protocol registration (console + $LOG_FILE)..."
echo "==== $(date '+%F %T') start pid=$$ ====" >> "$LOG_FILE"

# Multiport auto-probe is OFF by default — choose in CLI menu:
#   1=Clash单代理  2=多代理池(可现场测活)  3=直连
# Force pre-start multiport: GROKX_MULTIPORT_ON_START=1 ./start.sh
if [ "${GROKX_SKIP_MULTIPORT:-0}" != "1" ] && [ "${GROKX_MULTIPORT_ON_START:-0}" = "1" ]; then
    if [ -x "./flclash_multiport.sh" ]; then
        echo "[*] FlClash multiport: regen + probe live nodes → proxies.txt"
        if ./flclash_multiport.sh start; then
            LIVE_N=$(grep -cE '^[[:space:]]*http://' proxies.txt 2>/dev/null || echo 0)
            echo "[*] proxies.txt live count: $LIVE_N"
        else
            echo "[!] multiport probe failed (continue with existing proxies.txt)"
        fi
    fi
fi

if [ $# -eq 0 ]; then
    set -- --cli
fi

# Preserve interactive TTY for menu while logging stdout/stderr
if [ -t 0 ]; then
    "$PYTHON_EXE" -u register_protocol.py "$@" 2>&1 | tee -a "$LOG_FILE"
    # pipeline exit status of python (bash PIPESTATUS)
    EXIT_CODE=${PIPESTATUS[0]}
else
    "$PYTHON_EXE" -u register_protocol.py "$@" >> "$LOG_FILE" 2>&1
    EXIT_CODE=$?
fi

echo "==== $(date '+%F %T') exit=$EXIT_CODE ====" >> "$LOG_FILE"
echo ""
if [ $EXIT_CODE -ne 0 ]; then
    echo "Program exited with code $EXIT_CODE. See $LOG_FILE"
fi
exit $EXIT_CODE
