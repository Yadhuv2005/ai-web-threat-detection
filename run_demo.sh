#!/bin/bash
# ===================================================================
# AEGIS CYBER DEFENSE - Automated Demo Launcher
# ===================================================================

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

echo "=========================================================="
echo "  AEGIS CYBER DEFENSE: AI-Based Threat Detection System  "
echo "=========================================================="

# 1. Check Python installation
if ! command -v python3 &> /dev/null; then
    echo "[-] Python3 not found in standard PATH."
    echo "[!] Please ensure Python 3 is installed or Command Line Tools are enabled."
    exit 1
fi

# 2. Train model if not already saved
if [ ! -f "ml/saved_models/threat_classifier.pkl" ]; then
    echo "[*] Training initial NLP Threat Classifier..."
    python3 ml/train.py
else
    echo "[+] Found existing trained model at ml/saved_models/threat_classifier.pkl"
fi

# 3. Clean previous log file for fresh session
mkdir -p test_website/logs
> test_website/logs/access.log

echo "[*] Starting Target Website on http://127.0.0.1:8001..."
python3 test_website/app.py &
TARGET_PID=$!

sleep 1

echo "[*] Starting Central Monitoring Backend on http://127.0.0.1:8000..."
python3 backend/main.py &
BACKEND_PID=$!

cleanup() {
    echo ""
    echo "[*] Shutting down services..."
    kill $TARGET_PID 2>/dev/null
    kill $BACKEND_PID 2>/dev/null
    echo "[+] All services stopped safely."
    exit 0
}

trap cleanup SIGINT SIGTERM

sleep 2
echo ""
echo "=========================================================="
echo "  SERVICES ONLINE!"
echo "  - Target Test Website:  http://127.0.0.1:8001"
echo "  - Cyber SOC Dashboard:  http://127.0.0.1:8000"
echo "=========================================================="
echo "To test traffic, run in a separate terminal:"
echo "  python3 tests/generate_traffic.py 1"
echo ""
echo "Press Ctrl+C at any time to shut down both servers."
echo "=========================================================="

wait
