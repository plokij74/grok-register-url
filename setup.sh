#!/bin/bash
cd "$(dirname "$0")"

echo "Creating venv and installing deps..."
python3 -m venv .venv
. .venv/bin/activate
pip install -U pip
pip install -r requirements.txt

echo ""
echo "Done. Edit config.json (mail API / domains / proxy), then run ./start.sh"
