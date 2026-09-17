#!/bin/bash
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

echo "=========================================================="
echo "  1. Checking Python Environment..."
echo "=========================================================="

PYTHON_BIN="$PROJECT_DIR/venv/bin/python"

if [ ! -f "$PYTHON_BIN" ]; then
    echo "[*] Creating virtual environment..."
    python3 -m venv venv
    "$PYTHON_BIN" -m pip install -r requirements.txt
fi

echo "=========================================================="
echo "  2. Training AI Model (if needed)..."
echo "=========================================================="
if [ ! -f "ml/saved_models/threat_classifier.pkl" ]; then
    "$PYTHON_BIN" ml/train.py
fi

echo "=========================================================="
echo "  3. Launching Servers..."
echo "=========================================================="
mkdir -p test_website/logs

# Start Target Website in background and log to file
"$PYTHON_BIN" -m uvicorn test_website.app:app --host 127.0.0.1 --port 8001 > target_website.log 2>&1 &
TARGET_PID=$!

sleep 1

# Start Backend Server in background and log to file
"$PYTHON_BIN" -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 > backend.log 2>&1 &
BACKEND_PID=$!

cleanup() {
    echo ""
    echo "[*] Stopping servers..."
    kill $TARGET_PID 2>/dev/null
    kill $BACKEND_PID 2>/dev/null
    exit 0
}
trap cleanup SIGINT SIGTERM

sleep 2

echo ""
echo "=========================================================="
echo "  ✅ BOTH SERVERS ARE NOW RUNNING!"
echo ""
echo "  👉 Cyber Dashboard:  http://127.0.0.1:8000"
echo "  👉 Target Website:    http://127.0.0.1:8001"
echo "=========================================================="
echo "Keep this Terminal window open!"
echo "Press Ctrl + C when you want to stop the servers."
echo "=========================================================="

wait
