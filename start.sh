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

echo "Starting GrokX protocol registration (console + $LOG_FILE)..."
echo "==== $(date '+%F %T') start pid=$$ ====" >> "$LOG_FILE"

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
