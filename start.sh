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

echo "Starting GrokX protocol registration (console)..."
if [ $# -eq 0 ]; then
    "$PYTHON_EXE" register_protocol.py --cli
else
    "$PYTHON_EXE" register_protocol.py "$@"
fi
EXIT_CODE=$?

echo ""
if [ $EXIT_CODE -ne 0 ]; then
    echo "Program exited with code $EXIT_CODE."
fi
exit $EXIT_CODE
